package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.Rapid7Client.ApiResponse
import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogResponses
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResponseSanitizerTest {

    private val op = CatalogOp(name = "t", opId = "t", method = "GET", path = "/t", readOnly = true)

    private fun text(r: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult) =
        r.content.filterIsInstance<TextContent>().joinToString("\n") { it.text }

    @Test
    fun `htmlToText strips scripts, styles, comments, tags and re-escapes`() {
        val html = "<p>A &amp; B</p><script>x<y</script><style>.a{}</style><!-- c --><div>C\r\nD</div><br/>E &#65;&#x42; &nbsp;&unknown; &#xD800;"
        val out = ResponseSanitizer.htmlToText(html)
        assertEquals("A &amp; B\n\nC\nD\n\nE AB &amp;unknown; &amp;#xD800;", out)
        assertFalse(out.contains('<'))
        assertFalse(out.contains('>'))
    }

    @Test
    fun `entity decoding`() {
        assertEquals("<>\"' ©", ResponseSanitizer.decodeEntities("&lt;&gt;&quot;&apos;&nbsp;&copy;"))
        assertEquals("&bogus;", ResponseSanitizer.decodeEntities("&bogus;"))
        assertEquals("&#1;", ResponseSanitizer.decodeEntities("&#1;"))
        assertEquals("&#x7F;", ResponseSanitizer.decodeEntities("&#x7F;"))
        assertEquals("😀", ResponseSanitizer.decodeEntities("&#x1F600;"))
        assertEquals("&#99999999;", ResponseSanitizer.decodeEntities("&#99999999;"))
    }

    @Test
    fun `control characters are scrubbed but tabs and newlines survive`() {
        assertEquals("a\tb\nc", ResponseSanitizer.scrubControlCharacters("a\tb\u0007\u0000\nc"))
    }

    @Test
    fun `binary descriptor`() {
        val bytes = byteArrayOf(1, 2, 3)
        val json = JsonCodec.compact.parseToJsonElement(ResponseSanitizer.describeBinary(bytes, "application/zip; x=\"q\"", truncated = true)).jsonObject
        assertEquals("application/zip; x=\\\"q\\\"".replace("\\\"", "\""), json["contentType"]!!.jsonPrimitive.content)
        assertEquals(3, json["bytes"]!!.jsonPrimitive.content.toInt())
        assertEquals("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", json["sha256"]!!.jsonPrimitive.content)
        assertEquals("true", json["responseTruncated"]!!.jsonPrimitive.content)
        assertEquals("false", json["base64Truncated"]!!.jsonPrimitive.content)
        assertEquals("AQID", json["base64"]!!.jsonPrimitive.content)
        val noType = JsonCodec.compact.parseToJsonElement(ResponseSanitizer.describeBinary(bytes, null, false)).jsonObject
        assertEquals("application/octet-stream", noType["contentType"]!!.jsonPrimitive.content)
    }

    @Test
    fun `toToolResult dispatches on content type`() {
        val json = ResponseSanitizer.toToolResult(ApiResponse(200, true, "application/json;charset=UTF-8", text = """{"a":1}"""), op, ApiFamily.CONSOLE)
        assertContains(text(json), "\"a\": 1")
        assertFalse(json.isError == true)

        val html = ResponseSanitizer.toToolResult(ApiResponse(200, true, "text/html", text = "<b>hi</b>"), op, ApiFamily.CONSOLE)
        assertContains(text(html), "\nhi\n")

        val plain = ResponseSanitizer.toToolResult(ApiResponse(200, true, "text/plain", text = "x\u0001y"), op, ApiFamily.CONSOLE)
        assertContains(text(plain), "\nxy\n")

        // No content type: fall back to the catalog's documented success type.
        val untyped = ResponseSanitizer.toToolResult(ApiResponse(200, true, null, text = """{"b":2}"""), op, ApiFamily.CLOUD)
        assertContains(text(untyped), "\"b\": 2")
        val untypedPlain = ResponseSanitizer.toToolResult(ApiResponse(200, true, null, text = "raw"), op.copy(responses = CatalogResponses("text/plain")), ApiFamily.CLOUD)
        assertContains(text(untypedPlain), "\nraw\n")

        // Bytes with a textual content type are decoded rather than base64'd.
        val textBytes = ResponseSanitizer.toToolResult(ApiResponse(200, true, "text/csv", bytes = "a,b".toByteArray()), op, ApiFamily.CONSOLE)
        assertContains(text(textBytes), "\na,b\n")

        val binary = ResponseSanitizer.toToolResult(ApiResponse(200, true, "application/zip", bytes = byteArrayOf(9), truncated = true, limitBytes = 1), op, ApiFamily.CONSOLE)
        assertContains(text(binary), "\"responseTruncated\": true")
        assertFalse(text(binary).contains("Response body truncated"))

        val truncatedText = ResponseSanitizer.toToolResult(ApiResponse(200, true, "text/plain", text = "abc", truncated = true, limitBytes = 3), op, ApiFamily.CONSOLE)
        assertTrue(text(truncatedText).endsWith("[Response body truncated at 3 bytes; narrow the query (page size, filters) to see everything.]"))

        val xss = ResponseSanitizer.toToolResult(ApiResponse(200, true, "application/json", text = """{"proof":"<script>alert(1)</script>","note":"a &lt; b"}"""), op, ApiFamily.CONSOLE)
        assertFalse(text(xss).contains("<script>"))
        assertContains(text(xss), "&lt;script&gt;alert(1)&lt;/script&gt;")
        assertContains(text(xss), "a &lt; b")
        val plainXss = ResponseSanitizer.toToolResult(ApiResponse(200, true, "text/plain", text = "<img src=x onerror=alert(1)>"), op, ApiFamily.CONSOLE)
        assertFalse(text(plainXss).substringAfter(UNTRUSTED_BEGIN).contains('<'))

        val failed = ResponseSanitizer.toToolResult(ApiResponse(503, false, "application/json", text = ""), op, ApiFamily.CLOUD)
        assertTrue(failed.isError == true)
        assertContains(text(failed), "Cloud Integrations API v4 returned HTTP 503.")
        assertContains(text(failed), "(empty response body)")
    }

    /**
     * Regression: markup that arrives JSON-escaped must not come back literal.
     *
     * `neutralizeMarkup` runs on the raw wire text, where `<` contains no `<` for it to rewrite;
     * the budget then parses that text and re-encodes the tree, and the encoder emits the decoded
     * `<` verbatim. Escaping therefore round-tripped straight through the XSS defence. The test
     * above only ever used a literal `<script>`, which is why this survived.
     */
    @Test
    fun `JSON-escaped markup cannot survive the budget re-encode`() {
        // Six literal characters each — backslash, u, 0, 0, 3, c — not a Kotlin unicode escape.
        val lt = "\\u003c"
        val gt = "\\u003e"
        val wire = "{\"proof\":\"${lt}script${gt}alert(1)${lt}/script${gt}\",\"host\":\"${lt}img src=x onerror=alert(1)${gt}\"}"
        val out = text(ResponseSanitizer.toToolResult(ApiResponse(200, true, "application/json", text = wire), op, ApiFamily.CONSOLE))
        assertFalse(out.contains('<'), "escaped markup was re-encoded as a literal '<'")
        assertFalse(out.contains('>'), "escaped markup was re-encoded as a literal '>'")
        assertContains(out, "&lt;script&gt;alert(1)&lt;/script&gt;")
        assertContains(out, "&lt;img src=x onerror=alert(1)&gt;")
    }

    /** The encoder also re-emits DEL, which `scrubControlCharacters` had already removed. */
    @Test
    fun `JSON-escaped control characters cannot survive the budget re-encode`() {
        val wire = "{\"note\":\"a\\u007fb\"}"
        val out = text(ResponseSanitizer.toToolResult(ApiResponse(200, true, "application/json", text = wire), op, ApiFamily.CONSOLE))
        assertFalse(out.contains(''), "escaped DEL was re-encoded literally")
    }
}
