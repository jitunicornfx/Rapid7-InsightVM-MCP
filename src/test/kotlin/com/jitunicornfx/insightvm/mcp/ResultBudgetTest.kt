package com.jitunicornfx.insightvm.mcp

import kotlinx.serialization.json.JsonArray
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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ResultBudgetTest {

    /** A v3-shaped paged document with [n] records of roughly [width] characters each. */
    private fun pagedBody(n: Int, width: Int = 60, total: Int = n): String = buildJsonObject {
        putJsonArray("links") { add(buildJsonObject { put("href", "https://c:3780/api/3/assets"); put("rel", "self") }) }
        putJsonObject("page") { put("number", 0); put("size", n); put("totalPages", 1); put("totalResources", total) }
        putJsonArray("resources") {
            repeat(n) { i -> add(buildJsonObject { put("id", i); put("hostName", "h".repeat(width) + i) }) }
        }
    }.toString()

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
        assertContains(r.notice!!, CHEAPER_WAYS)
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
        assertContains(r.notice!!, "not JSON")
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
        // Deeper than the parser's recursion limit: parseOrNull must swallow the StackOverflowError.
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
