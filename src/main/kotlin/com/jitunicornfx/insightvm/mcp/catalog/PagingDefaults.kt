package com.jitunicornfx.insightvm.mcp.catalog

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Page-size policy for the operations that support paging.
 *
 * The v3 specification declares `default: 10, minimum: 1` and no maximum, so nothing stopped a
 * caller asking for `size=1000000` and having it forwarded verbatim. Two problems follow: an
 * omitted `size` yields ten records and a model that pages thousands of times, and an enormous
 * `size` is fetched, paid for in latency, and then trimmed away to fit the response budget.
 *
 * This lives OUTSIDE [ArgumentBinder] on purpose. The binder's contract is that it sends exactly
 * what the caller asked for and nothing else; policy belongs to the layer above it.
 */
object PagingDefaults {

    const val SIZE_PARAM = "size"
    const val PAGE_PARAM = "page"
    const val CURSOR_PARAM = "cursor"

    /**
     * Injected when the caller omits `size`. Ten (the specification's own default) makes the model
     * page endlessly; 500 fills the whole response budget with fat asset records. 100 leaves roughly
     * fourfold headroom and mirrors the sibling InsightIDR server's page default.
     */
    const val DEFAULT_PAGE_SIZE = 100

    /**
     * The largest `size` that is forwarded. Above roughly this, a page cannot render inside the
     * default budget, so the extra records are fetched and then dropped.
     */
    const val MAX_PAGE_SIZE = 500

    fun hasSize(op: CatalogOp): Boolean = op.params.any { it.isQuery && it.name == SIZE_PARAM }

    fun hasCursor(op: CatalogOp): Boolean = op.params.any { it.isQuery && it.name == CURSOR_PARAM }

    /** True for anything this policy applies to, or that the model should be told about. */
    fun isPaged(op: CatalogOp): Boolean = hasSize(op) || hasCursor(op)

    /** The specification's own `maximum` where it declares one, otherwise [MAX_PAGE_SIZE]. */
    fun maxSizeFor(op: CatalogOp, ceiling: Int = MAX_PAGE_SIZE): Int =
        op.params.firstOrNull { it.isQuery && it.name == SIZE_PARAM }
            ?.schema?.get("maximum")
            ?.let { (it as? JsonPrimitive)?.contentOrNull?.toIntOrNull() }
            ?.coerceAtMost(ceiling)
            ?: ceiling

    /**
     * The `size` an omitted one becomes for [op]: the configured [default], kept within the
     * operation's own range. [apply] injects it and the tool text states it, through this one
     * function, so the two cannot disagree.
     */
    fun defaultSizeFor(op: CatalogOp, default: Int, ceiling: Int = MAX_PAGE_SIZE): Int =
        default.coerceIn(1, maxSizeFor(op, ceiling))

    /**
     * [args] with `size` defaulted when absent and clamped when out of range; the identity for the
     * 292 operations that declare no `size` at all.
     *
     * A non-numeric `size` is deliberately left untouched so [ArgumentBinder] can produce its normal
     * actionable "must be an integer" message rather than having it silently replaced.
     */
    fun apply(
        op: CatalogOp,
        args: JsonObject,
        default: Int = DEFAULT_PAGE_SIZE,
        ceiling: Int = MAX_PAGE_SIZE,
    ): JsonObject {
        if (!hasSize(op)) return args
        val max = maxSizeFor(op, ceiling)
        val requested = args[SIZE_PARAM]?.takeUnless { it is JsonNull }
        val resolved: Int = when {
            requested == null -> defaultSizeFor(op, default, ceiling)
            else -> {
                val n = (requested as? JsonPrimitive)?.contentOrNull?.let(::asIntegerOrNull) ?: return args
                if (n in 1..max) return args
                n.coerceIn(1, max)
            }
        }
        return JsonObject(args + (SIZE_PARAM to JsonPrimitive(resolved)))
    }

    /**
     * Parse exactly the integer forms [ArgumentBinder.coerceScalar] accepts, saturated into `Int`.
     *
     * The clamp has to understand every form the binder will forward, or it is not a clamp. The
     * binder takes a `Long` and a whole-valued `Double` as well as a plain `Int`, so a check built
     * on `toIntOrNull` silently passed `size=1e6` and `size=99999999999` straight through — they
     * parsed as null here, returned the arguments untouched, and reached the API unbounded. Only
     * genuinely non-numeric input returns null now, which still leaves the binder to raise its own
     * actionable error rather than this file inventing one.
     */
    private fun asIntegerOrNull(raw: String): Int? {
        val text = raw.trim()
        val n = text.toLongOrNull()
            ?: text.toDoubleOrNull()?.takeIf { it == Math.floor(it) && !it.isInfinite() }?.toLong()
            ?: return null
        // Saturate rather than wrap: an out-of-Int-range request is still an over-large request.
        return n.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()).toInt()
    }
}
