package com.jitunicornfx.insightvm.mcp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * How many characters of InsightVM API data a single tool result may carry.
 *
 * This is the model-context budget, and it is a different thing from [Config.maxResponseBytes],
 * which only bounds memory while the body is read off the wire. A single page of assets runs to
 * hundreds of kilobytes and pretty-printing inflates it a further ~50%; a vulnerability's affected-
 * asset list runs to megabytes. Every API response funnels through
 * [ResponseSanitizer.toToolResult], so this one type bounds all 343 tools.
 *
 * Immutable. The process-wide value is installed once at startup from [Config.maxResultChars];
 * tests pass an explicit instance, so the ladder is testable without touching global state.
 */
data class ResultBudget(
    /** Ceiling on rendered API data, in characters. ~4 chars per token, so 200_000 is ~50k tokens. */
    val maxChars: Int = DEFAULT_MAX_CHARS,
    /**
     * Error bodies are never trimmed below this. A non-2xx body is the diagnostic the model needs
     * to correct itself; a small [maxChars] must not be able to erase it.
     */
    val errorFloorChars: Int = DEFAULT_ERROR_FLOOR_CHARS,
    /** A cut always emits at least this much, so the response's shape is still visible. */
    val sampleFloorChars: Int = DEFAULT_SAMPLE_FLOOR_CHARS,
    /**
     * Bodies larger than this are never parsed into a JSON tree — the tree costs several times the
     * string it came from. Above it the ladder degrades straight to a line-aware cut. The export
     * tool, not a bigger heap, is the answer for results this size.
     */
    val parseCeilingChars: Int = DEFAULT_PARSE_CEILING_CHARS,
) {
    /** The limit that actually applies to a response with this [ok] flag. */
    internal fun limitFor(ok: Boolean): Int =
        if (ok) maxChars else maxOf(maxChars, errorFloorChars)

    companion object {
        const val DEFAULT_MAX_CHARS = 200_000
        const val DEFAULT_ERROR_FLOOR_CHARS = 4_000
        const val DEFAULT_SAMPLE_FLOOR_CHARS = 1_000
        const val DEFAULT_PARSE_CEILING_CHARS = 12_000_000

        /** Key the in-band truncation marker is written under. */
        const val TRUNCATION_KEY = "_mcp_truncated"

        /**
         * Keys that are never candidates for structural trimming. `links` carries the `rel=next`
         * href, and `page` (v3) / `metadata` (v4) carry `totalResources` — the count that makes the
         * cheap `size=1` idiom work. Trimming either would destroy the caller's ability to page or
         * to learn how much it is missing.
         */
        internal val NEVER_TRIM_KEYS = setOf("links", "page", "metadata")

        @Volatile
        private var installed: ResultBudget = ResultBudget()

        /** The process-wide budget. One [Config] per process, so one budget per process. */
        val active: ResultBudget get() = installed

        /** Install the configured budget. Called once from Main before anything is served. */
        fun install(budget: ResultBudget) {
            installed = budget
        }
    }
}

/** Headroom for the truncation marker's final digits and the encoder's separators. */
private const val SAFETY_MARGIN = 512

/** Which rung of the ladder produced the rendered text. */
internal enum class BudgetStrategy { PRETTY, COMPACT, STRUCTURAL, LINE_CUT, HARD_CUT }

/**
 * A rendered body plus the server-authored notice that must accompany it.
 *
 * [notice] is null when nothing was compacted or dropped. When present it is emitted OUTSIDE the
 * untrusted envelope, so it can never be confused with — or forged by — API data.
 */
internal data class BudgetedBody(
    val text: String,
    val notice: String?,
    val strategy: BudgetStrategy,
)

/**
 * Why a body reached the line-aware cut rather than a structural trim. The cut notice names the
 * actual reason: a wrong one sends the model after a problem that is not there, and every one of
 * these used to be reported as "The response was not JSON".
 */
internal enum class CutReason {
    /** HTML or plain text, or a body that claimed to be JSON and did not parse. */
    NOT_JSON,

    /** Over [ResultBudget.parseCeilingChars], so it was never parsed: nothing was pruned or trimmed. */
    TOO_LARGE_TO_PARSE,

    /** Cut off by [Config.maxResponseBytes] before it ended, so it cannot parse. */
    TRUNCATED_AT_WIRE_CAP,

    /**
     * Parsed, but nested too deeply for the encoder. The parser handles deep objects without
     * recursion and the encoder does not, so hostile nesting can pass one and overflow the other.
     */
    TOO_DEEP_TO_ENCODE,

    /** Parsed and re-encoded, but with no top-level array to drop entries from. */
    NO_TRIMMABLE_ARRAY,
}

/**
 * Render [raw] into at most [ResultBudget.limitFor] characters, degrading through progressively
 * lossier strategies, and never throwing.
 *
 * The body is parsed at most ONCE; every rung re-encodes the same element. Deeply-nested,
 * attacker-controlled JSON can overflow the recursive parser — that is an [Error], not an
 * [Exception], so it would escape `apiTool`'s catch and tear down the session. Every rung swallows
 * it and falls through to the next, and the last rung cannot fail.
 *
 * @param json whether the body is expected to be JSON. HTML and plain text are never re-encoded:
 *   a text/plain body that happens to parse as a bare JSON number must not come back as one.
 * @param truncatedAtWire whether [Config.maxResponseBytes] cut the body short, which is why a JSON
 *   body would fail to parse; it only changes the reason a cut notice gives.
 */
internal fun renderWithinBudget(
    raw: String,
    budget: ResultBudget,
    ok: Boolean,
    json: Boolean,
    keepRecordLinks: Boolean = false,
    truncatedAtWire: Boolean = false,
): BudgetedBody {
    if (raw.isBlank()) return BudgetedBody(raw, null, BudgetStrategy.PRETTY)
    val limit = budget.limitFor(ok)

    if (!json) return asReceived(raw, limit, budget, CutReason.NOT_JSON)

    val tooLargeToParse = raw.length > budget.parseCeilingChars
    val parsed: JsonElement? = if (tooLargeToParse) null else parseOrNull(raw)

    // No tree. The wire cut is named first: that body is incomplete, and would not parse under any
    // ceiling (at the defaults a 16 MiB cut is always over the 12M-character ceiling as well).
    if (parsed == null) {
        val reason = when {
            truncatedAtWire -> CutReason.TRUNCATED_AT_WIRE_CAP
            tooLargeToParse -> CutReason.TOO_LARGE_TO_PARSE
            else -> CutReason.NOT_JSON
        }
        return asReceived(raw, limit, budget, reason)
    }

    val pruned = if (keepRecordLinks) Pruned(parsed, 0) else pruneRecordLinks(parsed)
    val element = pruned.element
    val stripNotice = if (pruned.removed > 0) strippedLinksNotice(pruned.removed) else null

    // Over the limit, compact is encoded FIRST. Pretty is never shorter than compact, so it is only
    // worth trying when compact fits and links were pruned (unpruned, compact <= raw for valid JSON,
    // since whitespace only adds, so pretty is over too). A multi-megabyte pruned page therefore no
    // longer pays for a pretty encode (about 1.5x the body, plus a scrub and a neutralise pass) that
    // was always thrown away. A raw body within the limit, the common case, still tries pretty first
    // and usually ends the ladder in one encode. Every path returns what the pretty-first ladder did.
    val early: String? = if (raw.length > limit) {
        encodeOrNull(JsonCodec.compact, element) ?: return asReceived(raw, limit, budget, CutReason.TOO_DEEP_TO_ENCODE)
    } else {
        null
    }

    // Rung 1 — pretty.
    if (early == null || (pruned.removed > 0 && early.length <= limit)) {
        val pretty = encodeOrNull(JsonCodec.pretty, element)
        if (pretty != null && pretty.length <= limit) {
            return BudgetedBody(pretty, stripNotice, BudgetStrategy.PRETTY)
        }
    }

    // Rung 2 — compact. Recovers the whitespace pretty added, which rescues bodies in the
    // [limit, ~2x limit] band. It does not shrink an already-dense API response.
    val compact = early ?: encodeOrNull(JsonCodec.compact, element)
        ?: return asReceived(raw, limit, budget, CutReason.TOO_DEEP_TO_ENCODE)
    if (compact.length <= limit) {
        return BudgetedBody(compact, join(stripNotice, compactedNotice(limit)), BudgetStrategy.COMPACT)
    }

    // Rung 3 — structural: drop entries from the largest trimmable top-level array, keeping the
    // document valid, parseable JSON.
    trimLargestArray(element, limit)?.let {
        return it.copy(notice = join(stripNotice, it.notice))
    }

    // Rung 4 — cut. The output is a prefix, not a JSON document; the notice says so.
    val cut = lineAwareCut(compact, limit, budget, CutReason.NO_TRIMMABLE_ARRAY)
    return cut.copy(notice = join(stripNotice, cut.notice))
}

/**
 * The body exactly as it arrived, for when it could not be rendered from a tree: whole when it
 * fits, otherwise cut with a notice naming [reason]. Before, a tree the encoder could not render
 * went to the cut even when it fitted, and was reported as CUT to its own length.
 */
private fun asReceived(raw: String, limit: Int, budget: ResultBudget, reason: CutReason): BudgetedBody =
    if (raw.length <= limit) BudgetedBody(raw, null, BudgetStrategy.PRETTY)
    else lineAwareCut(raw, limit, budget, reason)

private fun join(vararg parts: String?): String? =
    parts.filterNotNull().ifEmpty { null }?.joinToString("\n\n")

internal fun parseOrNull(raw: String): JsonElement? = try {
    JsonCodec.compact.parseToJsonElement(raw)
} catch (_: StackOverflowError) {
    null
} catch (_: Exception) {
    null
}

/**
 * Encode [element], neutralising the ENCODER'S OUTPUT rather than trusting the upstream pass.
 *
 * `ResponseSanitizer.neutralizeMarkup` only ever sees the raw wire body, where markup that arrived
 * JSON-escaped (`<script>`) carries no `<` for it to rewrite. Parsing decodes that escape
 * and the encoder re-emits it literally, so escaping round-tripped straight through the XSS defence
 * on the default rung of all 343 tools. Re-running it here closes that, and this is the right layer:
 * every JSON rung renders through this function, and every length in this file is measured through
 * it too, so the budget arithmetic stays self-consistent under the expansion.
 *
 * Both passes are idempotent here — the upstream pass already rewrote any literal `<`, and `&lt;`
 * contains nothing further to rewrite — so double-escaping is not possible.
 */
internal fun encodeOrNull(json: Json, element: JsonElement): String? = try {
    ResponseSanitizer.neutralizeMarkup(
        ResponseSanitizer.scrubControlCharacters(json.encodeToString(JsonElement.serializer(), element)),
    )
} catch (_: StackOverflowError) {
    null
} catch (_: Exception) {
    null
}

/**
 * Drop trailing entries from the largest trimmable array so the document fits, keeping it valid,
 * parseable JSON. Returns null when there is nothing worth trimming (a single deeply-nested object,
 * for instance), so the caller falls through to the cut.
 *
 * Entries are dropped from the TAIL: the API returns records in the order the caller sorted them,
 * so the head is always the records they asked for first. Only DIRECT children of the root are
 * considered — recursing would produce a valid-but-misleading document for a marginal saving.
 */
private fun trimLargestArray(root: JsonElement, limit: Int): BudgetedBody? {
    val key: String?
    val array: JsonArray
    when (root) {
        is JsonArray -> {
            key = null
            array = root
        }

        is JsonObject -> {
            val candidate = root.entries
                .filter { it.key !in ResultBudget.NEVER_TRIM_KEYS }
                .mapNotNull { entry -> (entry.value as? JsonArray)?.let { entry.key to it } }
                .maxByOrNull { it.second.size }
                ?: return null
            key = candidate.first
            array = candidate.second
        }

        else -> return null
    }
    if (array.size < 2) return null

    // One pass: encode each entry once and accumulate. No binary search, no repeated whole-document
    // encoding — the cost is O(total size), the same as the compact encode already performed.
    val lengths = array.map { (encodeOrNull(JsonCodec.compact, it) ?: return null).length }

    val shell = shellDocument(root, key, array.size)
    val shellLength = encodeOrNull(JsonCodec.compact, shell)?.length ?: return null
    val available = limit - shellLength - SAFETY_MARGIN
    if (available <= 0) return null

    var used = 0
    var keep = 0
    for (length in lengths) {
        // +1 for the separating comma.
        if (used + length + 1 > available) break
        used += length + 1
        keep++
    }
    if (keep == 0 || keep >= array.size) return null

    val kept = JsonArray(array.take(keep))
    val trimmed: JsonElement = if (key == null) {
        // A bare array keeps its JSON TYPE. Adding a sibling marker would turn it into an object
        // and break any consumer expecting an array; the notice carries the truth instead.
        kept
    } else {
        JsonObject(
            LinkedHashMap(root as JsonObject).apply {
                put(key, kept)
                // Overwrite any key of this name the API body already carried.
                put(ResultBudget.TRUNCATION_KEY, truncationMarker(key, keep, array.size))
            },
        )
    }
    val text = encodeOrNull(JsonCodec.compact, trimmed) ?: return null
    return BudgetedBody(text, droppedNotice(key, keep, array.size, limit), BudgetStrategy.STRUCTURAL)
}

/** The document as it will be emitted with an empty target array, to measure fixed overhead. */
private fun shellDocument(root: JsonElement, key: String?, total: Int): JsonElement =
    if (key == null) {
        JsonArray(emptyList())
    } else {
        JsonObject(
            LinkedHashMap(root as JsonObject).apply {
                put(key, JsonArray(emptyList()))
                put(ResultBudget.TRUNCATION_KEY, truncationMarker(key, total, total))
            },
        )
    }

private fun truncationMarker(arrayKey: String, kept: Int, total: Int): JsonObject = buildJsonObject {
    put("array", arrayKey)
    put("returned", kept)
    put("total", total)
    put("dropped", total - kept)
    put("reason", "result exceeded this MCP server's response budget")
    put(
        "note",
        "Server-authored marker inserted by $SERVER_NAME. Not part of the InsightVM API response. " +
            "The sibling 'page'/'metadata' object still describes the FULL page the API returned, so " +
            "its size/totalResources will not match the number of entries left here.",
    )
}

/**
 * Truncate [text] to the budget, preferring the last line boundary so a line-oriented body ends on
 * a complete record. The result is a PREFIX, not valid JSON; the notice says so.
 */
private fun lineAwareCut(text: String, limit: Int, budget: ResultBudget, reason: CutReason): BudgetedBody {
    val target = maxOf(limit, budget.sampleFloorChars).coerceAtMost(text.length)
    var slice = text.substring(0, target)
    val lastBreak = slice.lastIndexOf('\n')
    val strategy = if (lastBreak >= budget.sampleFloorChars) {
        slice = slice.substring(0, lastBreak)
        BudgetStrategy.LINE_CUT
    } else {
        BudgetStrategy.HARD_CUT
    }
    // Never emit a dangling half of a surrogate pair — substring can split one.
    if (slice.isNotEmpty() && slice.last().isHighSurrogate()) slice = slice.dropLast(1)
    return BudgetedBody(slice, cutNotice(text.length, slice.length, limit, reason, budget.parseCeilingChars), strategy)
}

// ---------------------------------------------------------------------------
// Notices. Server-authored: every value interpolated into one is either an integer this server
// computed or a name reduced by `safeNoticeKey`, and none contains the envelope markers, so they are
// safe to emit outside the fence.
// ---------------------------------------------------------------------------

internal const val NOTICE_TAG = "[insightvm-mcp]"

internal const val CHEAPER_WAYS =
    "Cheaper ways to get what you need:\n" +
        "  - Just need a COUNT? Re-run the same tool with size=1 and read page.totalResources (v3) or\n" +
        "    metadata.totalResources (v4). One tiny page answers 'how many' for a few hundred tokens\n" +
        "    instead of enumerating every record.\n" +
        "  - Need EVERY record? Use insightvm_export_to_file: it follows all pages on the server,\n" +
        "    writes NDJSON to a file and returns only a summary, so the cost is the same for 1 MB or 1 GB.\n" +
        "  - Need a SLICE? Lower 'size', set 'page', add a sort, or narrow the search body's filters.\n" +
        "Paging a whole result set through this conversation is never the right approach: enumerating\n" +
        "every asset costs millions of tokens through the chat and roughly a thousand through the\n" +
        "export tool."

private fun compactedNotice(limit: Int): String =
    "$NOTICE_TAG Large result rendered as COMPACT JSON (not pretty-printed) to fit the " +
        "$limit-character response budget. No data was dropped."

/**
 * Reduce an API-supplied JSON key to something that cannot forge structure in a notice.
 *
 * The trimmed array's key is the one piece of response-derived text any notice carries, and notices
 * are emitted OUTSIDE the untrusted fence, where the model reads them as server-authored. InsightVM
 * itself only ever uses fixed keys (`resources`, `data`), so this changes nothing in practice — it
 * is what makes the "no API content is interpolated" rule above true by construction rather than by
 * assumption about a remote server's behaviour.
 */
private fun safeNoticeKey(key: String): String =
    key.filter { it.isLetterOrDigit() || it == '_' || it == '-' }.take(64).ifEmpty { "top-level" }

private fun droppedNotice(key: String?, kept: Int, total: Int, limit: Int): String {
    val what = key?.let(::safeNoticeKey) ?: "top-level"
    return "$NOTICE_TAG This result was TRUNCATED to fit the $limit-character response budget " +
        "(${Config.ENV_MAX_RESULT_CHARS}). The data block above is still valid, parseable JSON.\n" +
        "Returned $kept of $total $what entries; ${total - kept} were dropped from the end.\n" +
        "Any 'page'/'metadata' object in the data still describes the full page the API returned, so " +
        "its counts will not match what is left here.\n" +
        "This notice is authoritative; the ${ResultBudget.TRUNCATION_KEY} object inside the data " +
        "block is a convenience copy only.\n" +
        CHEAPER_WAYS
}

private fun cutNotice(originalLength: Int, keptLength: Int, limit: Int, reason: CutReason, parseCeilingChars: Int): String =
    "$NOTICE_TAG This response was $originalLength characters and was CUT to $keptLength to fit " +
        "the $limit-character response budget (${Config.ENV_MAX_RESULT_CHARS}). The block above is a " +
        "PREFIX of the response and is NOT valid JSON — do not try to parse it as a whole document.\n" +
        cutReasonLine(reason, parseCeilingChars) +
        CHEAPER_WAYS

private fun cutReasonLine(reason: CutReason, parseCeilingChars: Int): String = when (reason) {
    CutReason.NOT_JSON -> "The response was not JSON.\n"
    CutReason.TOO_LARGE_TO_PARSE ->
        "The response was too large to parse (over $parseCeilingChars characters), so per-record links " +
            "were not stripped and no records were trimmed.\n"
    CutReason.TRUNCATED_AT_WIRE_CAP ->
        "The response was cut off at ${Config.ENV_MAX_RESPONSE_BYTES} before it ended, so it is incomplete " +
            "JSON that cannot be parsed: per-record links were not stripped and no records were trimmed.\n"
    CutReason.TOO_DEEP_TO_ENCODE ->
        "The response was JSON nested too deeply to re-encode, so it is shown as received: per-record " +
            "links were not stripped and no records were trimmed.\n"
    CutReason.NO_TRIMMABLE_ARRAY -> "The response had no top-level array to trim.\n"
}
