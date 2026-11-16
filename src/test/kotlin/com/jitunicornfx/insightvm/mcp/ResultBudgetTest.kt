package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import com.jitunicornfx.insightvm.mcp.tools.ExportTools
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import java.security.MessageDigest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** See `a pruned oversized body is trimmed exactly as before compact-first`. */
private const val GOLDEN_PRUNED_STRUCTURAL_SHA256 = "12eb72c5956b33d850c2721c3af59c7f48358f48e6c56b2331be0f534955652d"

class ResultBudgetTest {

    /** A v3-shaped paged document with [n] records of roughly [width] characters each. */
    private fun pagedBody(n: Int, width: Int = 60, total: Int = n): String = buildJsonObject {
        putJsonArray("links") { add(buildJsonObject { put("href", "https://c:3780/api/3/assets"); put("rel", "self") }) }
        putJsonObject("page") { put("number", 0); put("size", n); put("totalPages", 1); put("totalResources", total) }
        putJsonArray("resources") {
            repeat(n) { i -> add(buildJsonObject { put("id", i); put("hostName", "h".repeat(width) + i) }) }
        }
    }.toString()

    /** [pagedBody] as the v3 API really sends it: every record carries its own HATEOAS self link. */
    private fun linkedPagedBody(n: Int): String = buildJsonObject {
        putJsonArray("links") { add(buildJsonObject { put("href", "https://c:3780/api/3/assets?page=1"); put("rel", "next") }) }
        putJsonObject("page") { put("number", 0); put("size", n); put("totalPages", 1); put("totalResources", n) }
        putJsonArray("resources") {
            repeat(n) { i ->
                add(
                    buildJsonObject {
                        put("id", i)
                        put("hostName", "h".repeat(60) + i)
                        putJsonArray("links") { add(buildJsonObject { put("href", "https://c:3780/api/3/assets/$i"); put("rel", "self") }) }
                    },
                )
            }
        }
    }.toString()

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun render(raw: String, maxChars: Int = 200_000, ok: Boolean = true, json: Boolean = true) =
        renderWithinBudget(raw, ResultBudget(maxChars = maxChars), ok, json)

    // ------------------------------------------------------------------ rung 1

    @Test
    fun `a small json body is pretty-printed with no notice`() {
        val r = render("""{"a":1}""")
        assertEquals(BudgetStrategy.PRETTY, r.strategy)
        assertContains(r.text, "\"a\": 1")
        assertNull(r.notice, "the happy path must never append anything after the fence")
    }

    @Test
    fun `a blank body is passed through untouched`() {
        val r = render("")
        assertEquals("", r.text)
        assertNull(r.notice)
        assertEquals(BudgetStrategy.PRETTY, renderWithinBudget("   ", ResultBudget(), true, true).strategy)
    }

    // ------------------------------------------------------------------ rung 2

    @Test
    fun `a body that only fits when compact is compacted, losing nothing`() {
        val body = pagedBody(40)
        // Between the compact length and the pretty length: pretty overflows, compact fits.
        val limit = body.length + 200
        val r = render(body, maxChars = limit)
        assertEquals(BudgetStrategy.COMPACT, r.strategy)
        assertTrue(r.text.length <= limit)
        assertEquals(40, JsonCodec.compact.parseToJsonElement(r.text).jsonObject["resources"]!!.jsonArray.size, "no data dropped")
        assertContains(r.notice!!, "COMPACT JSON")
        assertContains(r.notice!!, "No data was dropped")
    }

    // ------------------------------------------------------------------ rung 3

    @Test
    fun `an oversized page is trimmed structurally into valid json`() {
        val body = pagedBody(200)
        val r = render(body, maxChars = 4_000)
        assertEquals(BudgetStrategy.STRUCTURAL, r.strategy)
        assertTrue(r.text.length <= 4_000, "actual ${r.text.length}")
        val doc = JsonCodec.compact.parseToJsonElement(r.text).jsonObject
        val kept = doc["resources"]!!.jsonArray
        assertTrue(kept.size in 1 until 200)
        // Head-first: entry 0 survives, so the caller keeps the records they sorted for.
        assertEquals(0, kept.first().jsonObject["id"]!!.jsonPrimitive.content.toInt())
        val marker = doc[ResultBudget.TRUNCATION_KEY]!!.jsonObject
        assertEquals("resources", marker["array"]!!.jsonPrimitive.content)
        assertEquals(kept.size, marker["returned"]!!.jsonPrimitive.content.toInt())
        assertEquals(200, marker["total"]!!.jsonPrimitive.content.toInt())
        assertEquals(200 - kept.size, marker["dropped"]!!.jsonPrimitive.content.toInt())
        assertContains(marker["note"]!!.jsonPrimitive.content, SERVER_NAME)
        assertContains(r.notice!!, "TRUNCATED")
        assertContains(r.notice!!, cheaperWays(exportAvailable = true))
    }

    /**
     * Regression: every trim and cut notice recommended insightvm_export_to_file, including under
     * --read-only and INSIGHTVM_DISABLE_EXPORT, where it is not registered.
     */
    @Test
    fun `the notices recommend the export tool only when it is registered`() {
        val body = pagedBody(200)
        val withExport = ResultBudget(maxChars = 4_000)
        val withoutExport = withExport.copy(exportAvailable = false)
        // As JSON the page is trimmed (the dropped notice); as text, one line, it is cut (the cut notice).
        for ((json, strategy) in listOf(true to BudgetStrategy.STRUCTURAL, false to BudgetStrategy.HARD_CUT)) {
            val offered = renderWithinBudget(body, withExport, true, json)
            val withheld = renderWithinBudget(body, withoutExport, true, json)
            assertEquals(strategy, withheld.strategy)
            assertContains(assertNotNull(offered.notice), ExportTools.EXPORT_TOOL)
            val notice = assertNotNull(withheld.notice)
            assertContains(notice, "size=1 and read page.totalResources")
            assertContains(notice, "Need a SLICE?")
            assertFalse(notice.contains(ExportTools.EXPORT_TOOL) || notice.contains("export tool"), notice)
            assertEquals(offered.text, withheld.text, "only the advice differs")
        }
    }

    @Test
    fun `structural trimming never touches links, page or metadata`() {
        val r = render(pagedBody(200), maxChars = 4_000)
        val doc = JsonCodec.compact.parseToJsonElement(r.text).jsonObject
        assertEquals(1, doc["links"]!!.jsonArray.size, "rel=next must survive so paging still works")
        assertEquals(200, doc["page"]!!.jsonObject["totalResources"]!!.jsonPrimitive.content.toInt())
        // v4 shape: metadata is protected too, and `data` is the array that gets trimmed.
        val v4 = buildJsonObject {
            putJsonObject("metadata") { put("cursor", "abc"); put("totalResources", 500) }
            putJsonArray("data") { repeat(200) { i -> add(buildJsonObject { put("id", i); put("x", "y".repeat(60)) }) } }
        }.toString()
        val r4 = render(v4, maxChars = 4_000)
        assertEquals(BudgetStrategy.STRUCTURAL, r4.strategy)
        val d4 = JsonCodec.compact.parseToJsonElement(r4.text).jsonObject
        assertEquals("abc", d4["metadata"]!!.jsonObject["cursor"]!!.jsonPrimitive.content)
        assertTrue(d4["data"]!!.jsonArray.size < 200)
    }

    /**
     * Golden for the compact-first ladder. Pruning used to force a pretty encode of a multi-megabyte
     * page (about 1.5x the body) that was then thrown away. Compact is now encoded first and pretty
     * is skipped whenever compact cannot fit; pretty is never shorter than compact, so the output has
     * to be byte-for-byte what the pretty-first ladder produced. [GOLDEN_PRUNED_STRUCTURAL_SHA256] was
     * captured from that ladder (3656fb7); re-capture it only for a deliberate change to the trim.
     */
    @Test
    fun `a pruned oversized body is trimmed exactly as before compact-first`() {
        val body = linkedPagedBody(200)
        val r = render(body, maxChars = 4_000)
        assertEquals(BudgetStrategy.STRUCTURAL, r.strategy)
        assertContains(r.notice!!, "Removed the per-record 'links' object from 200 record(s)")
        // The same tree arriving already pruned takes the structural rung with no pretty attempt.
        val prePruned = pruneRecordLinks(JsonCodec.compact.parseToJsonElement(body)).element.toString()
        assertEquals(renderWithinBudget(prePruned, ResultBudget(maxChars = 4_000), true, true).text, r.text)
        assertEquals(GOLDEN_PRUNED_STRUCTURAL_SHA256, sha256(r.text))
    }

    @Test
    fun `a pruned body over the limit whose compact form fits is compacted`() {
        val body = linkedPagedBody(40)
        val prunedCompact = pruneRecordLinks(JsonCodec.compact.parseToJsonElement(body)).element.toString()
        // Raw (with links) is over; pruned compact fits; pruned pretty (40 indented records) does not.
        val limit = prunedCompact.length + 100
        assertTrue(body.length > limit, "premise")
        val r = render(body, maxChars = limit)
        assertEquals(BudgetStrategy.COMPACT, r.strategy)
        assertEquals(prunedCompact, r.text)
        val notice = assertNotNull(r.notice)
        assertContains(notice, "Removed the per-record 'links'")
        assertContains(notice, "COMPACT JSON")
    }

    @Test
    fun `the notice warns that page counts no longer match the records`() {
        val r = render(pagedBody(200), maxChars = 4_000)
        assertContains(r.notice!!, "will not match")
    }

    @Test
    fun `a bare array keeps its json type when trimmed`() {
        val body = buildJsonArray { repeat(200) { i -> add(buildJsonObject { put("id", i); put("x", "y".repeat(60)) }) } }.toString()
        val r = render(body, maxChars = 4_000)
        assertEquals(BudgetStrategy.STRUCTURAL, r.strategy)
        val parsed = JsonCodec.compact.parseToJsonElement(r.text)
        assertTrue(parsed is JsonArray, "adding a marker would change the type and break array consumers")
        assertContains(r.notice!!, "top-level")
    }

    @Test
    fun `an object with no trimmable array falls through to the cut`() {
        // One deeply-nested object: nothing to trim, so the ladder must not stall.
        var deep = buildJsonObject { put("leaf", "z".repeat(9_000)) }
        repeat(5) { deep = buildJsonObject { put("n", deep) } }
        val r = render(deep.toString(), maxChars = 2_000)
        assertTrue(r.strategy == BudgetStrategy.HARD_CUT || r.strategy == BudgetStrategy.LINE_CUT)
        assertContains(r.notice!!, "no top-level array to trim")
    }

    @Test
    fun `an array of fewer than two entries is not trimmed`() {
        val one = buildJsonObject { putJsonArray("resources") { add(buildJsonObject { put("x", "y".repeat(9_000)) }) } }.toString()
        val r = render(one, maxChars = 2_000)
        assertTrue(r.strategy == BudgetStrategy.HARD_CUT || r.strategy == BudgetStrategy.LINE_CUT)
    }

    // ------------------------------------------------------------------ rung 4

    @Test
    fun `a non-json body is cut at a line boundary`() {
        val lines = (1..2_000).joinToString("\n") { "line $it " + "x".repeat(50) }
        val r = render(lines, maxChars = 5_000, json = false)
        assertEquals(BudgetStrategy.LINE_CUT, r.strategy)
        assertTrue(r.text.length <= 5_000)
        assertFalse(r.text.endsWith("x") && r.text.length == 5_000, "should stop on a line boundary")
        assertEquals(r.text, r.text.substringBeforeLast("\n") + "\n" + r.text.substringAfterLast("\n"))
        assertContains(r.notice!!, "not JSON")
        assertContains(r.notice!!, "PREFIX")
    }

    @Test
    fun `a cut never splits a surrogate pair`() {
        // Every character is a surrogate pair, so a naive substring lands mid-pair constantly.
        val body = "😀".repeat(4_000)
        for (limit in 2_000..2_010) {
            val r = render(body, maxChars = limit, json = false)
            assertFalse(r.text.isNotEmpty() && r.text.last().isHighSurrogate(), "dangling high surrogate at $limit")
        }
    }

    @Test
    fun `plain text is never re-encoded as json`() {
        // "123" parses as a bare JSON number; a text/plain body must come back verbatim.
        val r = render("123", json = false)
        assertEquals("123", r.text)
        assertNull(r.notice)
    }

    // ------------------------------------------------------------------ floors and ceilings

    @Test
    fun `an error body is never trimmed below the error floor`() {
        val err = buildJsonObject { put("message", "why it failed: " + "d".repeat(3_000)) }.toString()
        val ok = render(err, maxChars = 100, ok = true)
        val bad = render(err, maxChars = 100, ok = false)
        assertTrue(bad.text.length > ok.text.length, "the diagnostic survives a tiny budget")
        assertTrue(bad.text.length <= ResultBudget.DEFAULT_ERROR_FLOOR_CHARS)
    }

    @Test
    fun `a cut always emits at least the sample floor`() {
        val body = "z".repeat(50_000)
        val r = renderWithinBudget(body, ResultBudget(maxChars = 10, sampleFloorChars = 900), true, false)
        assertEquals(900, r.text.length)
    }

    @Test
    fun `a body above the parse ceiling is never parsed into a tree`() {
        val body = pagedBody(400)
        val budget = ResultBudget(maxChars = 4_000, parseCeilingChars = 100)
        val r = renderWithinBudget(body, budget, true, true)
        // No tree means no structural rung: it degrades straight to a cut.
        assertTrue(r.strategy == BudgetStrategy.HARD_CUT || r.strategy == BudgetStrategy.LINE_CUT)
        assertContains(r.notice!!, "too large to parse")
    }

    /**
     * Regression: valid JSON over the parse ceiling went down the not-JSON branch and its notice said
     * "The response was not JSON", which sends the model hunting for a format problem that is not
     * there. The ceiling stays (it is the memory guard); only the reason given changes.
     */
    @Test
    fun `valid json just over the parse ceiling is called too large, not 'not JSON'`() {
        val body = buildJsonArray { repeat(300) { i -> add(buildJsonObject { put("id", i); put("x", "y".repeat(40)) }) } }.toString()
        val r = renderWithinBudget(body, ResultBudget(maxChars = 2_000, parseCeilingChars = body.length - 1), true, true)
        val notice = assertNotNull(r.notice)
        assertFalse(notice.contains("not JSON"), notice)
        assertContains(notice, "too large to parse")
        assertContains(notice, "${body.length - 1}")
        assertContains(notice, "links were not stripped")
        // At the ceiling rather than one over it, the same body is parsed and trimmed structurally.
        val parsed = renderWithinBudget(body, ResultBudget(maxChars = 2_000, parseCeilingChars = body.length), true, true)
        assertEquals(BudgetStrategy.STRUCTURAL, parsed.strategy)
    }

    /**
     * Regression: a JSON body cut off by INSIGHTVM_MAX_RESPONSE_BYTES cannot parse, and was then
     * labelled "not JSON" as well. The notice now says it was cut at the wire.
     */
    @Test
    fun `a json body cut at the wire cap is not called 'not JSON'`() {
        val op = TEST_CATALOGS.getValue(ApiFamily.CONSOLE).ops.single { it.name == "get_assets" }
        val cut = pagedBody(400).take(20_000)
        val response = Rapid7Client.ApiResponse(200, true, "application/json", text = cut, truncated = true, limitBytes = 20_000)
        val result = ResponseSanitizer.toToolResult(response, op, ApiFamily.CONSOLE, ResultBudget(maxChars = 5_000))
        val notice = (result.content.single() as TextContent).text.substringAfter(UNTRUSTED_END)
        assertFalse(notice.contains("not JSON"), notice)
        assertContains(notice, Config.ENV_MAX_RESPONSE_BYTES)
        assertContains(notice, "PREFIX")

        // Cut at the wire AND over the ceiling (always both at the defaults): the wire cut is the
        // reason given, because that body is incomplete and would not parse under any ceiling.
        val both = renderWithinBudget(cut, ResultBudget(maxChars = 2_000, parseCeilingChars = 100), true, true, truncatedAtWire = true)
        val bothNotice = assertNotNull(both.notice)
        assertContains(bothNotice, Config.ENV_MAX_RESPONSE_BYTES)
        assertFalse(bothNotice.contains("too large to parse"), bothNotice)
    }

    /**
     * kotlinx-serialization (1.12+) refuses JSON past its nesting limit. Such a body is well-formed
     * JSON, so the notice must say it was too deep rather than "not JSON"; and a body that fits the
     * budget whole is passed through as received, with no notice claiming it was cut.
     */
    @Test
    fun `json over the parser's nesting limit is labelled so, and passed through when it fits`() {
        val depth = 50_000
        val deep = "{\"n\":".repeat(depth) + "1" + "}".repeat(depth)
        val refused = assertFailsWith<SerializationException>("premise: the parser refuses it") {
            JsonCodec.compact.parseToJsonElement(deep)
        }
        assertTrue(isNestingLimit(refused), "the library's nesting-limit message changed: ${refused.message}")
        assertTrue(parseJson(deep).tooDeep)
        assertFalse(parseJson("{\"n\":").tooDeep, "a malformed body is not reported as too deep")
        assertFalse(parseJson("[1]").tooDeep)

        val cutNotice = assertNotNull(render(deep, maxChars = 2_000).notice)
        assertFalse(cutNotice.contains("not JSON"), cutNotice)
        assertContains(cutNotice, "too deeply")

        val fits = render(deep, maxChars = deep.length)
        assertEquals(deep, fits.text)
        assertNull(fits.notice, "nothing was cut, so no notice may say it was")
    }

    /** The encoder still recurses: a tree built deeper than it can render yields null, not an Error. */
    @Test
    fun `encodeOrNull survives a tree too deep to encode`() {
        var tree: JsonElement = JsonPrimitive(1)
        repeat(500_000) { tree = JsonObject(mapOf("n" to tree)) }
        assertNull(encodeOrNull(JsonCodec.compact, tree))
    }

    @Test
    fun `limitFor applies the error floor only to failures`() {
        val b = ResultBudget(maxChars = 100, errorFloorChars = 4_000)
        assertEquals(100, b.limitFor(ok = true))
        assertEquals(4_000, b.limitFor(ok = false))
        assertEquals(9_000, ResultBudget(maxChars = 9_000).limitFor(ok = false), "a generous budget is not lowered")
    }

    // ------------------------------------------------------------------ robustness

    @Test
    fun `hostile input returns rather than throwing`() {
        // Far past the parser's nesting limit: parseOrNull must return null, never throw.
        val deep = "[".repeat(200_000) + "]".repeat(200_000)
        val r = render(deep, maxChars = 1_000)
        assertTrue(r.text.length <= maxOf(1_000, ResultBudget.DEFAULT_SAMPLE_FLOOR_CHARS))
        assertNotNull(r.notice)
        assertNull(parseOrNull(deep), "the guard is in parseOrNull")
        assertEquals("\"x\"", encodeOrNull(JsonCodec.pretty, JsonPrimitive("x")), "encodeOrNull passes valid input through")
    }

    @Test
    fun `invalid json under the limit is returned verbatim`() {
        val r = render("{not json")
        assertEquals("{not json", r.text)
        assertNull(r.notice)
    }

    @Test
    fun `the installed budget is process-wide and replaceable`() {
        val original = ResultBudget.active
        try {
            ResultBudget.install(ResultBudget(maxChars = 4_321))
            assertEquals(4_321, ResultBudget.active.maxChars)
        } finally {
            ResultBudget.install(original)
        }
        assertEquals(ResultBudget.DEFAULT_MAX_CHARS, ResultBudget().maxChars)
    }

    @Test
    fun `notices never contain the untrusted fence markers`() {
        // They are emitted outside the envelope, so they must not be forgeable as a fence.
        val notices = listOf(
            render(pagedBody(200), maxChars = 4_000).notice,
            render(pagedBody(40), maxChars = pagedBody(40).length + 200).notice,
            render("z".repeat(50_000), maxChars = 2_000, json = false).notice,
        )
        for (n in notices) {
            assertNotNull(n)
            assertFalse(n.contains(UNTRUSTED_BEGIN))
            assertFalse(n.contains(UNTRUSTED_END))
            assertContains(n, NOTICE_TAG)
        }
    }
}
