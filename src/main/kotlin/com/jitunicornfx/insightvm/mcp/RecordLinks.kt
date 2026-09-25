package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** A pruned document and how many `links` objects were removed from it. */
internal data class Pruned(val element: JsonElement, val removed: Int)

/** Keys whose array value holds the records of a paged or collection response: v3, then v4. */
internal val RECORD_ARRAY_KEYS = listOf("resources", "data")

private const val LINKS_KEY = "links"

/**
 * Depth, measured from a record object, at which a `links` key is still removed. 1 means the
 * record's own top-level `links` and nothing deeper — which is where effectively all of the saving
 * is. Deepening it costs an allocation per node for a marginal gain and risks deleting a `links`
 * field that is genuine data (a report's configured outputs, say).
 */
internal const val LINK_STRIP_MAX_DEPTH = 1

/**
 * Remove the per-record `links` objects from a paged or collection response.
 *
 * The v3 API is HAL-style: every record carries a `links` array whose only entry is usually its own
 * self URL, which is fully derivable from the record's `id`. Measured on a 25,000-asset
 * `get_affected_assets` response, that redundancy was 93% of the payload.
 *
 * What is deliberately NOT touched:
 *  - the root's own `links` — that is where `rel=next`/`rel=last` live, and dropping it would
 *    destroy the caller's ability to page;
 *  - the root's `page` (v3) / `metadata` (v4) object — `totalResources` is what makes the cheap
 *    `size=1` counting idiom work.
 *
 * Returns the original element unchanged (and `removed = 0`) when there is nothing to prune, so a
 * caller can cheaply tell whether anything happened.
 *
 * Recursion is bounded by [maxDepth], not by the document, so hostile nesting cannot overflow the
 * stack no matter how deep a record is.
 */
internal fun pruneRecordLinks(root: JsonElement, maxDepth: Int = LINK_STRIP_MAX_DEPTH): Pruned {
    if (maxDepth <= 0) return Pruned(root, 0)
    val count = IntArray(1)
    val pruned: JsonElement = when (root) {
        // Several v3 endpoints return a bare array of records.
        is JsonArray -> JsonArray(root.map { stripLinks(it, maxDepth, count) })

        is JsonObject -> {
            val key = RECORD_ARRAY_KEYS.firstOrNull { root[it] is JsonArray } ?: return Pruned(root, 0)
            val records = root[key] as JsonArray
            val stripped = JsonArray(records.map { stripLinks(it, maxDepth, count) })
            JsonObject(LinkedHashMap(root).apply { put(key, stripped) })
        }

        else -> return Pruned(root, 0)
    }
    return if (count[0] > 0) Pruned(pruned, count[0]) else Pruned(root, 0)
}

/** Remove `links` from [element] and, while [remainingDepth] allows, from what it contains. */
private fun stripLinks(element: JsonElement, remainingDepth: Int, count: IntArray): JsonElement {
    if (remainingDepth <= 0) return element
    return when (element) {
        is JsonObject -> {
            var changed = false
            val out = LinkedHashMap<String, JsonElement>(element.size)
            for ((key, value) in element) {
                if (key == LINKS_KEY) {
                    count[0]++
                    changed = true
                    continue
                }
                val replaced = stripLinks(value, remainingDepth - 1, count)
                if (replaced !== value) changed = true
                out[key] = replaced
            }
            if (changed) JsonObject(out) else element
        }

        is JsonArray -> {
            var changed = false
            val out = element.map { item ->
                val replaced = stripLinks(item, remainingDepth - 1, count)
                if (replaced !== item) changed = true
                replaced
            }
            if (changed) JsonArray(out) else element
        }

        else -> element
    }
}

/**
 * Server-authored, emitted outside the fence, and only when something was actually removed.
 *
 * The way back it offers first is the one the model can take itself: `include_links=true` on the
 * call. registerOperation reads and removes that argument for EVERY operation, including the
 * unpaged collection tools that are pruned here but do not list it in their schema (advertising it
 * on those would add about 9K characters to tools/list). The environment variable is only for the
 * operator.
 */
internal fun strippedLinksNotice(removed: Int): String =
    "$NOTICE_TAG Removed the per-record 'links' object from $removed record(s) to save context " +
        "(measured ~93% smaller on large pages). Each record's self URL is derivable from its id, and " +
        "the top-level 'links' (rel=next/last) and the page/metadata object are intact. Pass " +
        "${CatalogLoader.INCLUDE_LINKS_PROPERTY}=true on this call (or set " +
        "${Config.ENV_KEEP_RECORD_LINKS}=1 on the server) to keep them."
