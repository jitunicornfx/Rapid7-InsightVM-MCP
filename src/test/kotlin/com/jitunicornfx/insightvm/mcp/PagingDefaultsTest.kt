package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogParam
import com.jitunicornfx.insightvm.mcp.catalog.PagingDefaults
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class PagingDefaultsTest {

    private fun sizeParam(maximum: Int? = null) = CatalogParam(
        name = "size", `in` = "query",
        schema = buildJsonObject {
            put("type", "integer")
            put("description", "The number of records per page to retrieve.")
            if (maximum != null) put("maximum", maximum)
        },
    )

    private fun paged(maximum: Int? = null) = CatalogOp(
        name = "get_assets", opId = "getAssets", method = "GET", path = "/api/3/assets", readOnly = true,
        params = listOf(CatalogParam("page", "query", schema = buildJsonObject { put("type", "integer") }), sizeParam(maximum)),
    )

    private val unpaged = CatalogOp(
        name = "get_asset", opId = "getAsset", method = "GET", path = "/api/3/assets/{id}", readOnly = true,
        params = listOf(CatalogParam("id", "path", required = true, schema = buildJsonObject { put("type", "integer") })),
    )

    private fun size(args: JsonObject, op: CatalogOp = paged()) =
        PagingDefaults.apply(op, args)["size"]?.jsonPrimitive?.content

    @Test
    fun `an operation without a size parameter is untouched`() {
        val args = buildJsonObject { put("id", 7) }
        assertSame(args, PagingDefaults.apply(unpaged, args))
        assertFalse(PagingDefaults.hasSize(unpaged))
        assertFalse(PagingDefaults.isPaged(unpaged))
    }

    @Test
    fun `an omitted size is defaulted`() {
        assertEquals("100", size(buildJsonObject { put("page", 0) }))
        assertEquals(PagingDefaults.DEFAULT_PAGE_SIZE.toString(), size(JsonObject(emptyMap())))
        // An explicit null is the same as absent.
        assertEquals("100", size(buildJsonObject { put("size", JsonNull) }))
    }

    @Test
    fun `a configured default is honoured and itself clamped`() {
        val args = JsonObject(emptyMap())
        assertEquals("25", PagingDefaults.apply(paged(), args, default = 25)["size"]!!.jsonPrimitive.content)
        assertEquals(
            PagingDefaults.MAX_PAGE_SIZE.toString(),
            PagingDefaults.apply(paged(), args, default = 99_999)["size"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `an in-range size is passed through untouched`() {
        val args = buildJsonObject { put("size", 250) }
        assertSame(args, PagingDefaults.apply(paged(), args))
        assertEquals("1", size(buildJsonObject { put("size", 1) }))
        assertEquals("500", size(buildJsonObject { put("size", 500) }))
    }

    @Test
    fun `an out-of-range size is clamped at both ends`() {
        assertEquals("500", size(buildJsonObject { put("size", 1_000_000) }))
        assertEquals("1", size(buildJsonObject { put("size", 0) }))
        assertEquals("1", size(buildJsonObject { put("size", -20) }))
        // A numeric string is understood too — the binder accepts those.
        assertEquals("500", size(buildJsonObject { put("size", "9999") }))
    }

    @Test
    fun `a non-numeric size is left for the binder to reject`() {
        val args = buildJsonObject { put("size", "abc") }
        assertSame(args, PagingDefaults.apply(paged(), args), "the binder's actionable error is better than a silent replacement")
    }

    @Test
    fun `a specification maximum lowers the clamp but can never raise it`() {
        assertEquals(50, PagingDefaults.maxSizeFor(paged(maximum = 50)))
        assertEquals("50", size(buildJsonObject { put("size", 400) }, paged(maximum = 50)))
        assertEquals(PagingDefaults.MAX_PAGE_SIZE, PagingDefaults.maxSizeFor(paged(maximum = 100_000)))
        assertEquals(PagingDefaults.MAX_PAGE_SIZE, PagingDefaults.maxSizeFor(paged()))
    }

    @Test
    fun `the real catalog classifies the expected operations as paged`() {
        val console = TEST_CATALOGS.getValue(ApiFamily.CONSOLE).ops
        val cloud = TEST_CATALOGS.getValue(ApiFamily.CLOUD).ops
        assertEquals(43, console.count { PagingDefaults.hasSize(it) })
        assertEquals(0, console.count { PagingDefaults.hasCursor(it) })
        assertEquals(5, cloud.count { PagingDefaults.hasSize(it) })
        assertEquals(3, cloud.count { PagingDefaults.hasCursor(it) })
        // All three cursor operations also declare page/size, so the union is 48, not 51.
        assertEquals(48, (console + cloud).count { PagingDefaults.isPaged(it) })
        assertTrue(cloud.filter { PagingDefaults.hasCursor(it) }.all { PagingDefaults.hasSize(it) })
        // Nothing this policy touches is destructive or admin, so it can never widen a dangerous call.
        assertTrue((console + cloud).filter { PagingDefaults.isPaged(it) }.none { it.admin })
    }

    /**
     * Regression: the clamp must cover every numeric form the binder will forward.
     *
     * `ArgumentBinder.coerceScalar` accepts a whole-valued double and a Long for an `integer`
     * parameter, so `size=1e6` and `size=99999999999` used to fail `toIntOrNull` here, fall through
     * untouched, and reach the API unbounded — `size` is declared `integer` with no `maximum` in all
     * 48 paged operations, which makes MAX_PAGE_SIZE the only bound there is.
     */
    @Test
    fun `oversized page sizes are clamped in every numeric form the binder accepts`() {
        val op = TEST_CATALOGS.getValue(ApiFamily.CONSOLE).ops.first { PagingDefaults.hasSize(it) }
        fun sizeAfter(raw: String): String? =
            PagingDefaults.apply(op, buildJsonObject { put("size", JsonPrimitive(raw)) })["size"]?.jsonPrimitive?.content

        assertEquals("500", sizeAfter("1000000"), "plain integer")
        assertEquals("500", sizeAfter("1e6"), "scientific notation")
        assertEquals("500", sizeAfter("1000000.0"), "whole-valued double")
        assertEquals("500", sizeAfter("99999999999"), "beyond Int range")
        assertEquals("1", sizeAfter("-5"), "negative saturates to the floor")
        assertEquals("1", sizeAfter("0"), "zero saturates to the floor")
        assertEquals("250", sizeAfter("250"), "an in-range value is left alone")
        // Genuinely non-numeric input is still passed through untouched so the binder — not this
        // file — raises the actionable error.
        assertEquals("abc", sizeAfter("abc"), "non-numeric is left for the binder to reject")
        assertEquals("NaN", sizeAfter("NaN"), "NaN is left for the binder to reject")
    }
}
