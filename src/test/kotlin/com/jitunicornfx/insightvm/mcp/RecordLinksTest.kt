package com.jitunicornfx.insightvm.mcp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

class RecordLinksTest {

    private fun selfLinks(id: Int) = buildJsonArray {
        add(buildJsonObject { put("href", "https://console.test:3780/api/3/assets/$id"); put("rel", "self") })
    }

    /** A v3 paged document: top-level links + page + `resources`, each record carrying its self link. */
    private fun v3(n: Int) = buildJsonObject {
        putJsonArray("links") { add(buildJsonObject { put("href", "…?page=1"); put("rel", "next") }) }
        putJsonObject("page") { put("number", 0); put("size", n); put("totalResources", 9999) }
        putJsonArray("resources") {
            repeat(n) { i -> add(buildJsonObject { put("id", i); put("links", selfLinks(i)) }) }
        }
    }

    @Test
    fun `v3 records lose their links while paging metadata survives`() {
        val (pruned, removed) = pruneRecordLinks(v3(5))
        assertEquals(5, removed)
        val doc = pruned.jsonObject
        assertEquals("next", doc["links"]!!.jsonArray.single().jsonObject["rel"]!!.jsonPrimitive.content)
        assertEquals(9999, doc["page"]!!.jsonObject["totalResources"]!!.jsonPrimitive.content.toInt())
        val records = doc["resources"]!!.jsonArray
        assertEquals(5, records.size)
        assertTrue(records.all { "links" !in it.jsonObject })
        assertTrue(records.all { "id" in it.jsonObject }, "the id the self URL is derivable from stays")
    }

    @Test
    fun `v4 records under data are pruned and metadata survives`() {
        val body = buildJsonObject {
            putJsonObject("metadata") { put("cursor", "abc"); put("totalResources", 42) }
            putJsonArray("data") {
                repeat(3) { i -> add(buildJsonObject { put("id", i); put("links", selfLinks(i)) }) }
            }
        }
        val (pruned, removed) = pruneRecordLinks(body)
        assertEquals(3, removed)
        val doc = pruned.jsonObject
        assertEquals("abc", doc["metadata"]!!.jsonObject["cursor"]!!.jsonPrimitive.content)
        assertTrue(doc["data"]!!.jsonArray.all { "links" !in it.jsonObject })
    }

    @Test
    fun `a bare array of records is pruned in place`() {
        val body = buildJsonArray { repeat(4) { i -> add(buildJsonObject { put("id", i); put("links", selfLinks(i)) }) } }
        val (pruned, removed) = pruneRecordLinks(body)
        assertEquals(4, removed)
        assertTrue(pruned is JsonArray)
        assertTrue(pruned.jsonArray.all { "links" !in it.jsonObject })
    }

    @Test
    fun `resources wins over data when a document somehow carries both`() {
        val body = buildJsonObject {
            putJsonArray("resources") { add(buildJsonObject { put("id", 1); put("links", selfLinks(1)) }) }
            putJsonArray("data") { add(buildJsonObject { put("id", 2); put("links", selfLinks(2)) }) }
        }
        val (pruned, removed) = pruneRecordLinks(body)
        assertEquals(1, removed, "only the v3 record array is treated as the records")
        assertTrue("links" !in pruned.jsonObject["resources"]!!.jsonArray.single().jsonObject)
        assertTrue("links" in pruned.jsonObject["data"]!!.jsonArray.single().jsonObject)
    }

    @Test
    fun `depth one leaves nested links alone and depth two reaches them`() {
        val body = buildJsonObject {
            putJsonArray("resources") {
                add(
                    buildJsonObject {
                        put("id", 1)
                        put("links", selfLinks(1))
                        putJsonObject("configuration") { put("links", selfLinks(99)) }
                    },
                )
            }
        }
        val shallow = pruneRecordLinks(body, maxDepth = 1)
        assertEquals(1, shallow.removed)
        val record = shallow.element.jsonObject["resources"]!!.jsonArray.single().jsonObject
        assertTrue("links" !in record)
        assertTrue("links" in record["configuration"]!!.jsonObject, "nested links are data, not self URLs")

        val deep = pruneRecordLinks(body, maxDepth = 2)
        assertEquals(2, deep.removed)
        assertTrue("links" !in deep.element.jsonObject["resources"]!!.jsonArray.single().jsonObject["configuration"]!!.jsonObject)
    }

    @Test
    fun `nothing to prune returns the original instance untouched`() {
        val noLinks = buildJsonObject { putJsonArray("resources") { add(buildJsonObject { put("id", 1) }) } }
        val r = pruneRecordLinks(noLinks)
        assertEquals(0, r.removed)
        assertSame(noLinks, r.element, "an unchanged document must not be reallocated")

        // No record array at all: a single-resource GET.
        val single = buildJsonObject { put("id", 1); put("links", selfLinks(1)) }
        assertEquals(0, pruneRecordLinks(single).removed)
        assertSame(single, pruneRecordLinks(single).element, "the root's own links are never touched")

        // maxDepth 0 is the identity.
        assertSame(noLinks, pruneRecordLinks(noLinks, maxDepth = 0).element)
        val v3doc = v3(2)
        assertEquals(0, pruneRecordLinks(v3doc, maxDepth = 0).removed)

        // A scalar root, and a record array of non-objects.
        assertEquals(0, pruneRecordLinks(kotlinx.serialization.json.JsonPrimitive(7)).removed)
        val scalars = buildJsonObject { putJsonArray("resources") { add(kotlinx.serialization.json.JsonPrimitive(1)) } }
        assertEquals(0, pruneRecordLinks(scalars).removed)
    }

    @Test
    fun `deeply nested records cannot overflow the stack`() {
        // Recursion is bounded by maxDepth, not by the document.
        var nested: JsonObject = buildJsonObject { put("leaf", 1) }
        repeat(100_000) { nested = buildJsonObject { put("n", nested) } }
        val body = buildJsonObject {
            putJsonArray("resources") { add(buildJsonObject { put("links", selfLinks(1)); put("deep", nested) }) }
        }
        assertEquals(1, pruneRecordLinks(body).removed)
    }

    @Test
    fun `the notice names the count and the way back`() {
        val notice = strippedLinksNotice(500)
        assertContains(notice, "500 record(s)")
        // The model cannot set an environment variable; the per-call argument is the way back it can
        // actually take, so it must come first.
        assertContains(notice, "include_links=true")
        assertTrue(notice.indexOf("include_links=true") < notice.indexOf(Config.ENV_KEEP_RECORD_LINKS))
        assertContains(notice, Config.ENV_KEEP_RECORD_LINKS)
        assertContains(notice, NOTICE_TAG)
        assertFalse(notice.contains(UNTRUSTED_BEGIN))
        assertFalse(notice.contains(UNTRUSTED_END))
    }

    @Test
    fun `pruning is what keeps a large page inside the budget`() {
        // The headline measurement, in miniature: links dominate a reference list.
        val refs = buildJsonObject {
            putJsonArray("resources") { repeat(400) { i -> add(buildJsonObject { put("id", i); put("links", selfLinks(i)) }) } }
        }
        val full = refs.toString().length
        val stripped = pruneRecordLinks(refs).element.toString().length
        assertTrue(stripped * 5 < full, "expected a large cut, got $stripped vs $full")

        // And end to end: the same body renders on the PRETTY rung once pruned, but not if kept.
        val budget = ResultBudget(maxChars = 12_000)
        assertEquals(BudgetStrategy.PRETTY, renderWithinBudget(refs.toString(), budget, true, json = true).strategy)
        assertTrue(
            renderWithinBudget(refs.toString(), budget, true, json = true, keepRecordLinks = true).strategy != BudgetStrategy.PRETTY,
            "keeping links should push the same body past the budget",
        )
    }
}
