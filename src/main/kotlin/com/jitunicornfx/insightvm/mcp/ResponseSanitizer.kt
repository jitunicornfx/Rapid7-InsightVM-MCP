package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.Rapid7Client.ApiResponse
import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import java.security.MessageDigest
import java.util.Base64

/**
 * Converts raw API responses into model-safe tool results.
 *
 *  - JSON is pretty-printed.
 *  - HTML (policy rationale/remediation/proof endpoints) is reduced to plain text: `<script>` and
 *    `<style>` blocks are removed with their content, tags are stripped, entities are decoded, and
 *    the result is re-escaped so no markup can reach a client that renders tool output.
 *  - Plain text has control characters scrubbed.
 *  - Binary payloads (zip log bundles) are never dumped into the conversation: a small JSON
 *    descriptor (size, sha256, content type) plus a capped base64 prefix is returned instead.
 *
 * Everything that originated from the API is then wrapped in the untrusted-data fence.
 */
object ResponseSanitizer {

    /**
     * How much of a binary payload is inlined as base64. Base64 costs 4 characters per 3 bytes and
     * the model can do nothing with an opaque blob, so this is sized to identify a payload (magic
     * bytes, a header) rather than to carry one — 256 KiB of base64 was 349,528 characters, well
     * past the whole response budget on its own.
     */
    const val MAX_INLINE_BINARY_BYTES = 4_096

    private val SCRIPT_STYLE = Regex("(?is)<(script|style)\\b[^>]*>.*?</\\1\\s*>")
    private val COMMENT = Regex("(?s)<!--.*?-->")
    private val BLOCK_BREAK = Regex("(?i)<\\s*(/?(p|div|br|li|tr|h[1-6]|ul|ol|table|section|article|pre|blockquote)|hr)\\b[^>]*>")
    private val TAG = Regex("<[^>]*>")
    private val ENTITY = Regex("&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{1,31});")
    private val CONTROL = Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]")
    private val MULTI_BLANK = Regex("\\n{3,}")
    private val TRAILING_WS = Regex("[ \\t]+\\n")

    private val NAMED_ENTITIES = mapOf(
        "amp" to "&", "lt" to "<", "gt" to ">", "quot" to "\"", "apos" to "'", "nbsp" to " ",
        "copy" to "©", "reg" to "®", "trade" to "™", "mdash" to "—", "ndash" to "–", "hellip" to "…",
        "laquo" to "«", "raquo" to "»", "ldquo" to "“", "rdquo" to "”", "lsquo" to "‘", "rsquo" to "’",
    )

    /** Reduce HTML to escaped plain text. The output contains no `<`, `>` or raw `&`. */
    fun htmlToText(html: String): String {
        var s = html.replace("\r\n", "\n")
        s = SCRIPT_STYLE.replace(s, " ")
        s = COMMENT.replace(s, " ")
        s = BLOCK_BREAK.replace(s, "\n")
        s = TAG.replace(s, " ")
        s = decodeEntities(s)
        s = scrubControlCharacters(s)
        s = s.lines().joinToString("\n") { it.trim().replace(Regex("[ \\t]{2,}"), " ") }
        s = MULTI_BLANK.replace(s, "\n\n").trim()
        return escapeMarkup(s)
    }

    /** Decode numeric and common named HTML entities; unknown entities are left as-is. */
    internal fun decodeEntities(text: String): String = ENTITY.replace(text) { m ->
        val body = m.groupValues[1]
        when {
            body.startsWith("#x") || body.startsWith("#X") ->
                body.substring(2).toIntOrNull(16)?.let(::codePointOrNull) ?: m.value
            body.startsWith("#") -> body.substring(1).toIntOrNull()?.let(::codePointOrNull) ?: m.value
            else -> NAMED_ENTITIES[body.lowercase()] ?: m.value
        }
    }

    private fun codePointOrNull(cp: Int): String? =
        if (cp in 0x20..0x10FFFF && cp !in 0xD800..0xDFFF && cp != 0x7F) String(Character.toChars(cp)) else null

    /** Escape the three characters that could re-form markup. */
    internal fun escapeMarkup(text: String): String =
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    /**
     * Replace the two characters that can open or close an HTML tag. API data (host names, banners,
     * vulnerability proofs, descriptions) is attacker-influenced and MCP clients frequently render tool
     * output as Markdown/HTML; `&lt;`/`&gt;` keep the text readable and reversible for the model while
     * making `<script>` and friends inert. `&` is left alone so already-escaped data is not double-escaped.
     */
    internal fun neutralizeMarkup(text: String): String = text.replace("<", "&lt;").replace(">", "&gt;")

    /** Remove C0/C1-ish control characters except tab and newline. */
    fun scrubControlCharacters(text: String): String = CONTROL.replace(text, "")

    /** Format a binary payload as a JSON descriptor with a capped base64 prefix. */
    fun describeBinary(bytes: ByteArray, contentType: String?, truncated: Boolean): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val inline = bytes.copyOf(minOf(bytes.size, MAX_INLINE_BINARY_BYTES))
        return buildString {
            append("{\n")
            append("  \"contentType\": \"").append(contentType?.let(::escapeJson) ?: "application/octet-stream").append("\",\n")
            append("  \"bytes\": ").append(bytes.size).append(",\n")
            append("  \"sha256\": \"").append(digest).append("\",\n")
            append("  \"responseTruncated\": ").append(truncated).append(",\n")
            append("  \"base64Truncated\": ").append(inline.size < bytes.size).append(",\n")
            append("  \"base64\": \"").append(Base64.getEncoder().encodeToString(inline)).append("\"\n")
            append("}")
        }
    }

    private fun escapeJson(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")

    /**
     * Convert an API response into a tool result, marking non-2xx responses as errors.
     *
     * Sanitisation runs BEFORE the budget: `neutralizeMarkup` turns `<` into `&lt;`, a 4x expansion
     * on the worst input (InsightVM embeds HTML proofs inside JSON strings), so budgeting first
     * would let a "200,000-character" result reach the model as 800,000. Neutralisation is
     * JSON-validity-preserving — `<`/`>` are never structural — so the structural rung still has a
     * real tree to trim.
     */
    fun toToolResult(
        response: ApiResponse,
        op: CatalogOp,
        family: ApiFamily,
        budget: ResultBudget = ResultBudget.active,
    ): CallToolResult {
        val ct = response.contentType?.lowercase().orEmpty()
        // The response's own content type wins; the catalog's documented type is only a fallback
        // for responses that omit it.
        val effectiveType = ct.ifEmpty { op.responses.success }
        val binary = response.bytes != null && !looksTextual(ct)
        val sanitized: String
        val isJson: Boolean
        when {
            binary -> {
                sanitized = describeBinary(response.bytes!!, response.contentType, response.truncated)
                isJson = true
            }
            response.bytes != null -> {
                sanitized = neutralizeMarkup(scrubControlCharacters(response.bytes.toString(Charsets.UTF_8)))
                isJson = false
            }
            // htmlToText already scrubs and escapes; a second pass would double-escape.
            effectiveType.startsWith("text/html") -> {
                sanitized = htmlToText(response.text.orEmpty())
                isJson = false
            }
            else -> {
                sanitized = neutralizeMarkup(scrubControlCharacters(response.text.orEmpty()))
                isJson = effectiveType.contains("json")
            }
        }
        val rendered = renderWithinBudget(sanitized, budget, response.ok, isJson)
        val text = buildString {
            if (!response.ok) {
                append("${family.displayName} returned HTTP ${response.status}.")
                statusHint(response.status, family)?.let { append(" $it") }
                append("\n")
            }
            if (rendered.text.isBlank()) {
                append(if (response.ok) "Success (HTTP ${response.status}, empty response body)." else "(empty response body)")
            } else {
                append(wrapUntrusted(rendered.text))
            }
            // Server-authored, outside the fence, and only ever present when something was actually
            // compacted, dropped or cut — the happy path must end at UNTRUSTED_END.
            rendered.notice?.let { append("\n\n").append(it) }
            if (response.truncated && response.bytes == null) {
                append("\n[Response body truncated at ${response.limitBytes} bytes; narrow the query (page size, filters) to see everything.]")
            }
        }
        return CallToolResult(content = listOf(TextContent(text)), isError = !response.ok)
    }

    private fun looksTextual(contentType: String): Boolean =
        contentType.startsWith("text/") || contentType.contains("json") || contentType.contains("xml") ||
            contentType.contains("javascript") || contentType.contains("x-www-form-urlencoded")
}
