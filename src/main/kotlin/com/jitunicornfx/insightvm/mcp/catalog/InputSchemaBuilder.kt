package com.jitunicornfx.insightvm.mcp.catalog

import com.jitunicornfx.insightvm.mcp.Config
import com.jitunicornfx.insightvm.mcp.tools.ExportTools
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * What this server is configured to do that a tool's own text states: the `size` an omitted one
 * becomes, whether the export tool exists to be pointed at, and whether per-record links are
 * stripped. The text used to be fixed when the tools were built, so it said 100 under
 * `INSIGHTVM_DEFAULT_PAGE_SIZE=25`, recommended an export tool that `--read-only` and
 * `INSIGHTVM_DISABLE_EXPORT` never register, and said links were stripped under
 * `INSIGHTVM_KEEP_RECORD_LINKS=1`. A model acts on what the text says, so each of those was advice
 * the server then contradicted.
 */
data class ToolTextContext(
    val defaultPageSize: Int = PagingDefaults.DEFAULT_PAGE_SIZE,
    val exportEnabled: Boolean = true,
    val keepRecordLinks: Boolean = false,
) {
    companion object {
        fun of(config: Config): ToolTextContext =
            ToolTextContext(config.defaultPageSize, config.exportEnabled, config.keepRecordLinks)
    }
}

/**
 * Turns a [CatalogOp] into the MCP tool description and JSON-Schema input.
 *
 * All of it is paid for by every session in tools/list before the first call, so nothing is added
 * here that the model cannot act on. The route names the family by its version alone (`[v3 GET
 * /api/3/assets]`), and parameters carry no path-or-query hint: the binder routes each argument by
 * its name, so the hint changed nothing and cost about 10K characters across the catalog.
 */
object InputSchemaBuilder {

    const val CONFIRM_VALUE = "EXECUTE"

    /** Tool description: summary, cleaned spec description, the HTTP route and any safety markers. */
    fun describe(op: CatalogOp, family: ApiFamily, text: ToolTextContext): String = buildString {
        if (op.summary.isNotBlank()) append(op.summary)
        if (op.description.isNotBlank()) {
            if (isNotEmpty()) append(" — ")
            append(op.description)
        }
        if (isNotEmpty()) append(' ')
        append("[${family.apiVersion} ${op.method} ${op.path}]")
        if (op.admin) append(" [ADMIN: executes an arbitrary console command; requires confirm=\"$CONFIRM_VALUE\"]")
        else if (op.destructive) append(" [destructive]")
        if (PagingDefaults.isPaged(op)) append(pagingGuidance(op, family, text))
    }

    /**
     * The short form of the result-size policy, appended to paged tools only. A tool description is
     * paid on every session, so this stays terse; the long form lives in the truncation notice,
     * which is only paid when the model has already made the expensive choice.
     *
     * Each sentence states what this server does as configured. The default size comes from the
     * same [PagingDefaults.defaultSizeFor] that injects it, the export tool is named only when it is
     * registered and would accept [op], and the links sentence is left out when links are kept. The
     * count idiom names the one field [family] returns.
     */
    internal fun pagingGuidance(op: CatalogOp, family: ApiFamily, text: ToolTextContext): String {
        val sentences = buildList {
            if (PagingDefaults.hasSize(op)) {
                add(
                    "'size' defaults to ${PagingDefaults.defaultSizeFor(op, text.defaultPageSize)} and is clamped to " +
                        "${PagingDefaults.maxSizeFor(op)}.",
                )
                add("For a COUNT ONLY, call with size=1 and read ${countField(family)} — a few hundred tokens instead of enumerating.")
            }
            if (text.exportEnabled && ExportTools.exportable(op)) {
                add("To read EVERY record use ${ExportTools.EXPORT_TOOL}, which pages on the server and returns only a summary.")
            }
            if (!text.keepRecordLinks) add("Per-record 'links' are stripped to save context.")
        }
        return if (sentences.isEmpty()) "" else sentences.joinToString(" ", prefix = " Paged: ")
    }

    /** Where a page states the total: v3 in `page`, v4 in `metadata`. */
    private fun countField(family: ApiFamily): String = when (family) {
        ApiFamily.CONSOLE -> "page.totalResources"
        ApiFamily.CLOUD -> "metadata.totalResources"
    }

    /** JSON-Schema for the tool input: one property per path/query parameter, plus `body` and `confirm` where applicable. */
    fun build(op: CatalogOp, text: ToolTextContext): ToolSchema {
        val required = mutableListOf<String>()
        val properties = buildJsonObject {
            for (p in op.params) {
                put(p.name, sizeAwareSchema(p, op, text))
                if (p.required) required += p.name
            }
            op.body?.let { body ->
                val schema = buildJsonObject {
                    body.schema.forEach { (k, v) -> if (k != "description") put(k, v) }
                    val original = (body.schema["description"] as? JsonPrimitive)?.content
                    val prefix = if (body.isJson) "Request body (JSON)." else "Request body (${body.contentType})."
                    put("description", if (original.isNullOrBlank()) prefix else "$prefix $original")
                }
                put(CatalogLoader.BODY_PROPERTY, schema)
                if (body.required) required += CatalogLoader.BODY_PROPERTY
            }
            if (PagingDefaults.isPaged(op)) {
                put(
                    CatalogLoader.INCLUDE_LINKS_PROPERTY,
                    buildJsonObject {
                        put("type", "boolean")
                        // Why links are stripped is in the description's paging text; this only says
                        // what the knob does and what the server does without it.
                        put("description", "Keep each record's 'links' (true) or strip them (false). Defaults to ${text.keepRecordLinks}.")
                    },
                )
            }
            if (op.admin) {
                put(
                    CatalogLoader.CONFIRM_PROPERTY,
                    buildJsonObject {
                        put("type", "string")
                        putJsonArray("enum") { add(JsonPrimitive(CONFIRM_VALUE)) }
                        put("description", "Must be exactly \"$CONFIRM_VALUE\" to acknowledge that this runs a command on the Security Console.")
                    },
                )
                required += CatalogLoader.CONFIRM_PROPERTY
            }
        }
        return ToolSchema(properties = properties, required = required.ifEmpty { null })
    }

    /** The keys of the `size` schema that are restated from this server's policy rather than copied. */
    private val SIZE_POLICY_KEYS = setOf("default", "maximum", "description")

    /**
     * The `size` parameter restated to match what this server does. The specification's
     * `default: 10` is not what an omitted `size` yields here, and a client that fills in schema
     * defaults sent it and so bypassed [PagingDefaults] altogether; the specification declares no
     * maximum at all. `default` and `maximum` now come from the same functions [PagingDefaults.apply]
     * uses.
     */
    private fun sizeAwareSchema(p: CatalogParam, op: CatalogOp, text: ToolTextContext): JsonObject {
        if (!p.isQuery || p.name != PagingDefaults.SIZE_PARAM) return p.schema
        val default = PagingDefaults.defaultSizeFor(op, text.defaultPageSize)
        val max = PagingDefaults.maxSizeFor(op)
        val original = (p.schema["description"] as? JsonPrimitive)?.content.orEmpty()
        val policy = "Defaults to $default on this server; values above $max are clamped so a page can fit the response budget."
        return buildJsonObject {
            p.schema.forEach { (k, v) -> if (k !in SIZE_POLICY_KEYS) put(k, v) }
            put("default", default)
            put("maximum", max)
            put("description", if (original.isBlank()) policy else "$original $policy")
        }
    }
}
