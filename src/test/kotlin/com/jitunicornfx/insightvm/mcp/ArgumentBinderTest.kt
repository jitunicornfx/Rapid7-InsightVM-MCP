package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.ArgumentBinder
import com.jitunicornfx.insightvm.mcp.catalog.CatalogBody
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogParam
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ArgumentBinderTest {

    private fun schema(type: String, vararg enum: String): JsonObject = buildJsonObject {
        put("type", type)
        if (enum.isNotEmpty()) putJsonArray("enum") { enum.forEach { add(JsonPrimitive(it)) } }
    }

    private val op = CatalogOp(
        name = "t", opId = "t", method = "PUT", path = "/api/3/sites/{id}/tags/{tagId}", readOnly = false,
        params = listOf(
            CatalogParam("id", "path", required = true, schema = schema("integer")),
            CatalogParam("tagId", "path", required = true, schema = schema("string")),
            CatalogParam("page", "query", schema = schema("integer")),
            CatalogParam("active", "query", schema = schema("boolean")),
            CatalogParam("sort", "query", array = true, schema = buildJsonObject { put("type", "array"); putJsonObject("items") { put("type", "string") } }),
            CatalogParam("kind", "query", schema = schema("string", "a", "b")),
            CatalogParam("ratio", "query", schema = schema("number")),
        ),
        body = CatalogBody("application/json", required = false, schema = schema("object")),
    )

    private fun args(vararg pairs: Pair<String, Any?>): JsonObject = buildJsonObject {
        pairs.forEach { (k, v) ->
            when (v) {
                null -> put(k, JsonNull)
                is String -> put(k, v)
                is Number -> put(k, v)
                is Boolean -> put(k, v)
                is JsonObject -> put(k, v)
                is JsonArray -> put(k, v)
                is List<*> -> putJsonArray(k) { v.forEach { add(JsonPrimitive(it.toString())) } }
                else -> error("unsupported $v")
            }
        }
    }

    @Test
    fun `binds path, query, arrays, enums and body`() {
        val bound = ArgumentBinder.bind(
            op,
            args("id" to 42, "tagId" to "a b/c", "page" to "3", "active" to true, "sort" to listOf("id,ASC", "name,DESC"), "kind" to "b", "ratio" to 0.25, "body" to buildJsonObject { put("x", 1) }),
        )
        assertEquals(HttpMethod.Put, bound.method)
        assertEquals("/api/3/sites/42/tags/a%20b%2Fc", bound.path)
        assertEquals(listOf("3"), bound.query["page"])
        assertEquals(listOf("true"), bound.query["active"])
        assertEquals(listOf("id,ASC", "name,DESC"), bound.query["sort"])
        assertEquals(listOf("b"), bound.query["kind"])
        assertEquals(listOf("0.25"), bound.query["ratio"])
        assertEquals(buildJsonObject { put("x", 1) }, bound.jsonBody)
        assertNull(bound.rawBody)
    }

    @Test
    fun `null and absent optionals are skipped`() {
        val bound = ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "page" to null))
        assertTrue(bound.query.isEmpty())
        assertNull(bound.jsonBody)
    }

    @Test
    fun `a scalar is accepted for an array parameter`() {
        assertEquals(listOf("id"), ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "sort" to "id")).query["sort"])
    }

    @Test
    fun `unknown arguments are rejected`() {
        val e = assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "extra" to 1)) }
        assertTrue(e.message!!.contains("'extra'"))
        assertTrue(e.message!!.contains("Accepted:"))
    }

    @Test
    fun `missing required path parameter`() {
        val e = assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1)) }
        assertTrue(e.message!!.contains("tagId"))
    }

    @Test
    fun `integer coercion`() {
        val s = schema("integer")
        assertEquals("12", ArgumentBinder.coerceScalar(s, JsonPrimitive("12"), "n"))
        assertEquals("12", ArgumentBinder.coerceScalar(s, JsonPrimitive(12.0), "n"))
        assertEquals("-3", ArgumentBinder.coerceScalar(s, JsonPrimitive(-3), "n"))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive(1.5), "n") }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive("abc"), "n") }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive("Infinity"), "n") }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, buildJsonObject { }, "n") }
    }

    @Test
    fun `boolean and number coercion`() {
        assertEquals("true", ArgumentBinder.coerceScalar(schema("boolean"), JsonPrimitive("TRUE"), "b"))
        assertEquals("false", ArgumentBinder.coerceScalar(schema("boolean"), JsonPrimitive(false), "b"))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(schema("boolean"), JsonPrimitive("yes"), "b") }
        assertEquals("2.5", ArgumentBinder.coerceScalar(schema("number"), JsonPrimitive("2.5"), "r"))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(schema("number"), JsonPrimitive("x"), "r") }
        assertEquals("raw", ArgumentBinder.coerceScalar(JsonObject(emptyMap()), JsonPrimitive("raw"), "s"))
    }

    @Test
    fun `enum membership is enforced`() {
        val e = assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(schema("string", "a", "b"), JsonPrimitive("c"), "kind") }
        assertTrue(e.message!!.contains("a, b"))
    }

    @Test
    fun `strings are bounded and may not contain line breaks or NUL`() {
        val s = schema("string")
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive("x".repeat(ArgumentBinder.MAX_STRING_LENGTH + 1)), "s") }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive("a\r\nb"), "s") }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.coerceScalar(s, JsonPrimitive("a\u0000b"), "s") }
        assertEquals("x".repeat(ArgumentBinder.MAX_STRING_LENGTH), ArgumentBinder.coerceScalar(s, JsonPrimitive("x".repeat(ArgumentBinder.MAX_STRING_LENGTH)), "s"))
    }

    @Test
    fun `path segments reject dot segments and empty values`() {
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "..")) }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to ".")) }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "")) }
        assertEquals("/a/x%3Fy%23z%25", ArgumentBinder.substitutePath("/a/{v}", mapOf("v" to "x?y#z%")))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.substitutePath("/a/{v}", emptyMap()) }
    }

    /**
     * Regression: `encodeURLPathPart` leaves `;` alone, so `instance="..;"` reached the wire as
     * `/api/3/reports/5/history/..;`. A Tomcat-style front end strips `;...` path parameters before
     * normalising, which leaves `..` and retargets the DELETE at `/api/3/reports/5` itself.
     */
    @Test
    fun `path segments encode the path-parameter delimiter and refuse dot segments ahead of it`() {
        val deleteInstance = TEST_CATALOGS.getValue(ApiFamily.CONSOLE).ops.single { it.name == "delete_report_instance" }
        fun bind(instance: String) = ArgumentBinder.bind(deleteInstance, args("id" to 5, "instance" to instance))

        for (dotted in listOf("..;", ".;", "..;x", ".;jsessionid=1", "..;/")) {
            val e = assertFailsWith<IllegalArgumentException>("'$dotted' must be refused") { bind(dotted) }
            assertTrue(e.message!!.contains("'.' or '..'"), e.message)
        }
        assertEquals("/api/3/reports/5/history/a%3Bb=c", bind("a;b=c").path)
        assertEquals("/api/3/reports/5/history/latest", bind("latest").path)
        // Only the part before the first ';' can collapse a level; a dot run after it is inert text.
        assertEquals("/api/3/reports/5/history/x%3B..", bind("x;..").path)
        assertEquals("/api/3/reports/5/history/...%3B", bind("...;").path)
        assertEquals("/a/%3B", ArgumentBinder.substitutePath("/a/{v}", mapOf("v" to ";")))
    }

    @Test
    fun `array parameters reject objects and oversize lists`() {
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "sort" to buildJsonObject { })) }
        val big = buildJsonArray { repeat(ArgumentBinder.MAX_ARRAY_ITEMS + 1) { add(JsonPrimitive("x")) } }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "sort" to big)) }
    }

    @Test
    fun `json body type, depth and size checks`() {
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "body" to "string")) }
        val arrayOp = op.copy(body = CatalogBody("application/json", true, schema("array")))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(arrayOp, args("id" to 1, "tagId" to "t", "body" to buildJsonObject { })) }
        assertEquals(buildJsonArray { add(JsonPrimitive(1)) }, ArgumentBinder.bind(arrayOp, args("id" to 1, "tagId" to "t", "body" to buildJsonArray { add(JsonPrimitive(1)) })).jsonBody)
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(arrayOp, args("id" to 1, "tagId" to "t")) }
        val stringOp = op.copy(body = CatalogBody("application/json", true, schema("string")))
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(stringOp, args("id" to 1, "tagId" to "t", "body" to 5)) }
        assertEquals(JsonPrimitive("s"), ArgumentBinder.bind(stringOp, args("id" to 1, "tagId" to "t", "body" to "s")).jsonBody)
        val untypedOp = op.copy(body = CatalogBody("application/json", true, JsonObject(mapOf("type" to JsonPrimitive("integer")))))
        assertEquals(JsonPrimitive(5), ArgumentBinder.bind(untypedOp, args("id" to 1, "tagId" to "t", "body" to 5)).jsonBody)

        var deep: JsonObject = buildJsonObject { put("leaf", 1) }
        repeat(ArgumentBinder.MAX_BODY_DEPTH + 2) { deep = buildJsonObject { put("n", deep) } }
        val e = assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "body" to deep)) }
        assertTrue(e.message!!.contains("nested deeper"))
        assertTrue(ArgumentBinder.depthOf(deep) > ArgumentBinder.MAX_BODY_DEPTH)
        assertEquals(1, ArgumentBinder.depthOf(JsonPrimitive(1)))
        assertEquals(3, ArgumentBinder.depthOf(buildJsonObject { putJsonArray("a") { add(buildJsonObject { }) } }))

        val huge = buildJsonObject { put("x", "y".repeat(ArgumentBinder.MAX_BODY_BYTES)) }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "body" to huge)) }
    }

    @Test
    fun `text bodies`() {
        val textOp = op.copy(body = CatalogBody("text/plain", true, schema("string")))
        val bound = ArgumentBinder.bind(textOp, args("id" to 1, "tagId" to "t", "body" to "help"))
        assertEquals("help", bound.rawBody)
        assertEquals("text/plain", bound.rawContentType.toString())
        assertNull(bound.jsonBody)
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(textOp, args("id" to 1, "tagId" to "t", "body" to 7)) }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(textOp, args("id" to 1, "tagId" to "t", "body" to "x".repeat(ArgumentBinder.MAX_BODY_BYTES + 1))) }
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(textOp, args("id" to 1, "tagId" to "t")) }
    }

    @Test
    fun `confirm is an accepted argument only for admin ops`() {
        assertFailsWith<IllegalArgumentException> { ArgumentBinder.bind(op, args("id" to 1, "tagId" to "t", "confirm" to "EXECUTE")) }
        val admin = op.copy(admin = true)
        ArgumentBinder.bind(admin, args("id" to 1, "tagId" to "t", "confirm" to "EXECUTE"))
    }
}
