package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogBody
import com.jitunicornfx.insightvm.mcp.catalog.CatalogFilter
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogMeta
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogParam
import com.jitunicornfx.insightvm.mcp.catalog.InputSchemaBuilder
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CatalogTest {

    private val v3 get() = TEST_CATALOGS.getValue(ApiFamily.CONSOLE)
    private val v4 get() = TEST_CATALOGS.getValue(ApiFamily.CLOUD)

    private fun op(name: String, method: String = "GET", path: String = "/x", tag: String = "T", admin: Boolean = false, params: List<CatalogParam> = emptyList()) =
        CatalogOp(name = name, opId = name, method = method, path = path, tag = tag, readOnly = method == "GET", destructive = method == "DELETE", admin = admin, params = params)

    private fun catalog(family: ApiFamily, vararg ops: CatalogOp) =
        Catalog(CatalogMeta(family = family.id, opCount = ops.size), ops.toList())

    // ---------------------------------------------------------------- loader

    @Test
    fun `bundled catalogs load with expected shape`() {
        assertEquals(330, v3.ops.size)
        assertEquals(13, v4.ops.size)
        assertEquals("console", v3.meta.family)
        assertEquals(64, v3.meta.specSha256.length)
        assertEquals(180, v3.ops.count { it.readOnly })
        assertEquals(57, v3.ops.count { it.destructive })
        assertEquals(1, v3.ops.count { it.admin })
        assertTrue(v4.ops.all { it.name.startsWith("cloud_") })
        assertTrue(v4.ops.none { op -> op.params.any { it.name == "region" } })
        val execute = v3.ops.single { it.admin }
        assertEquals("execute_command", execute.name)
        assertEquals("text/plain", execute.body!!.contentType)
        assertEquals("application/zip", v3.ops.single { it.name == "get_logs" }.responses.success)
        assertTrue(v3.ops.single { it.name == "get_logs" }.responses.binary)
    }

    @Test
    fun `loader rejects malformed json and unknown families`() {
        assertFailsWith<IllegalStateException> { CatalogLoader.parse("{not json", ApiFamily.CONSOLE) }
        val wrongFamily = """{"meta":{"family":"cloud","opCount":0},"ops":[]}"""
        assertFailsWith<IllegalStateException> { CatalogLoader.parse(wrongFamily, ApiFamily.CONSOLE) }
        assertEquals(0, CatalogLoader.parse("""{"meta":{"family":"console","opCount":0},"ops":[]}""", ApiFamily.CONSOLE).ops.size)
    }

    @Test
    fun `loader invariants`() {
        fun bad(vararg ops: CatalogOp, family: ApiFamily = ApiFamily.CONSOLE): String =
            assertFailsWith<IllegalStateException> { CatalogLoader.validate(catalog(family, *ops), family) }.message!!

        assertTrue(bad(op("Bad-Name")).contains("invalid tool name"))
        assertTrue(bad(op("dup"), op("dup")).contains("duplicate"))
        assertTrue(bad(op("no_prefix"), family = ApiFamily.CLOUD).contains("prefix"))
        assertTrue(bad(op("m", method = "HEAD")).contains("unsupported method"))
        assertTrue(bad(op("p", path = "x")).contains("start with"))
        assertTrue(bad(op("r").copy(readOnly = false)).contains("readOnly"))
        assertTrue(bad(op("t", path = "/a/{id}")).contains("placeholders"))
        assertTrue(bad(op("t", params = listOf(CatalogParam("id", "path", schema = JsonObject(emptyMap()))))).contains("placeholders"))
        assertTrue(bad(op("h", params = listOf(CatalogParam("x", "header", schema = JsonObject(emptyMap()))))).contains("location"))
        assertTrue(bad(op("b", params = listOf(CatalogParam("body", "query", schema = JsonObject(emptyMap()))))).contains("reserved"))
        assertTrue(bad(op("d", params = listOf(CatalogParam("q", "query", schema = JsonObject(emptyMap())), CatalogParam("q", "query", schema = JsonObject(emptyMap()))))).contains("duplicate parameter"))
        assertTrue(bad(op("s").copy(summary = "<b>x</b>")).contains("markup"))
        assertTrue(bad(op("c").copy(body = CatalogBody("application/xml", true, JsonObject(emptyMap())))).contains("content type"))
        val count = assertFailsWith<IllegalStateException> { CatalogLoader.validate(Catalog(CatalogMeta("console", opCount = 3), listOf(op("a"))), ApiFamily.CONSOLE) }
        assertTrue(count.message!!.contains("opCount"))
        assertFailsWith<IllegalStateException> { CatalogLoader.load(ApiFamily.CONSOLE).let { CatalogLoader.validate(it, ApiFamily.CLOUD) } }
    }

    // ---------------------------------------------------------------- filter

    @Test
    fun `filter chain`() {
        val cats = mapOf(
            ApiFamily.CONSOLE to catalog(
                ApiFamily.CONSOLE,
                op("get_site", tag = "Site"), op("delete_site", method = "DELETE", tag = "Site"),
                op("get_user", tag = "User"), op("execute_command", method = "POST", tag = "Administration", admin = true),
            ),
            ApiFamily.CLOUD to catalog(ApiFamily.CLOUD, op("cloud_get_sites", tag = "Site")),
        )
        fun names(f: ToolFilter) = CatalogFilter.select(cats, f).map { it.op.name }

        assertEquals(listOf("get_site", "delete_site", "get_user", "cloud_get_sites"), names(ToolFilter()))
        assertEquals(listOf("get_site", "get_user", "cloud_get_sites"), names(ToolFilter(readOnly = true)))
        assertEquals(listOf("get_site", "delete_site", "cloud_get_sites"), names(ToolFilter(tags = setOf("SITE"))))
        assertEquals(listOf("get_user"), names(ToolFilter(excludeTags = setOf("site"))))
        assertEquals(listOf("get_site", "delete_site", "get_user", "execute_command", "cloud_get_sites"), names(ToolFilter(allowAdminCommands = true)))
        assertEquals(listOf("cloud_get_sites"), names(ToolFilter(families = setOf(ApiFamily.CLOUD))))
        assertEquals(listOf("get_site", "get_user"), names(ToolFilter(nameGlobs = listOf("get_?ite", "*user"))))
        assertEquals(emptyList(), names(ToolFilter(nameGlobs = listOf("nothing"))))
        // read-only never lets the admin POST through, even when enabled.
        assertEquals(listOf("get_site", "get_user", "cloud_get_sites"), names(ToolFilter(readOnly = true, allowAdminCommands = true)))

        val summary = CatalogFilter.summarize(CatalogFilter.select(cats, ToolFilter(readOnly = true, tags = setOf("Site"))), cats, ToolFilter(readOnly = true, tags = setOf("Site")))
        assertTrue(summary.startsWith("registered 2/5 API tools (console=1, cloud=1)"), summary)
        assertTrue(summary.contains("read-only") && summary.contains("tags=Site"), summary)
        val loud = CatalogFilter.summarize(emptyList(), cats, ToolFilter(allowAdminCommands = true, excludeTags = setOf("User"), nameGlobs = listOf("x*")))
        assertTrue(loud.contains("ADMIN COMMANDS ENABLED") && loud.contains("exclude-tags=User") && loud.contains("tools=x*"), loud)
        assertFalse(CatalogFilter.summarize(emptyList(), cats, ToolFilter()).contains("["))
    }

    @Test
    fun `glob conversion escapes regex metacharacters`() {
        assertTrue(CatalogFilter.globToRegex("get_*").matches("get_sites"))
        assertFalse(CatalogFilter.globToRegex("get_*").matches("xget_sites"))
        assertTrue(CatalogFilter.globToRegex("a.b").matches("a.b"))
        assertFalse(CatalogFilter.globToRegex("a.b").matches("axb"))
        assertTrue(CatalogFilter.globToRegex("a?c").matches("abc"))
    }

    // ---------------------------------------------------------------- schema builder

    @Test
    fun `input schema includes params, body and confirm`() {
        val createSite = v3.ops.single { it.name == "create_site" }
        val schema = InputSchemaBuilder.build(createSite)
        val props = schema.properties!!
        assertTrue("body" in props)
        assertEquals(listOf("body"), schema.required)
        assertTrue(props["body"]!!.jsonObject["description"]!!.jsonPrimitive.content.startsWith("Request body (JSON)."))
        assertEquals("object", props["body"]!!.jsonObject["type"]!!.jsonPrimitive.content)

        val getAssets = v3.ops.single { it.name == "get_assets" }
        val s2 = InputSchemaBuilder.build(getAssets)
        assertNull(s2.required)
        assertTrue(s2.properties!!["sort"]!!.jsonObject["description"]!!.jsonPrimitive.content.endsWith("(Query parameter.)"))
        assertEquals("array", s2.properties!!["sort"]!!.jsonObject["type"]!!.jsonPrimitive.content)

        val admin = v3.ops.single { it.admin }
        val s3 = InputSchemaBuilder.build(admin)
        assertEquals(listOf("body", "confirm"), s3.required)
        assertEquals("EXECUTE", s3.properties!!["confirm"]!!.jsonObject["enum"]!!.jsonArray.single().jsonPrimitive.content)
        assertTrue(s3.properties!!["body"]!!.jsonObject["description"]!!.jsonPrimitive.content.startsWith("Request body (text/plain)."))

        val desc = InputSchemaBuilder.describe(admin, ApiFamily.CONSOLE)
        assertTrue(desc.contains("[ADMIN:"))
        val del = InputSchemaBuilder.describe(v3.ops.single { it.name == "delete_site" }, ApiFamily.CONSOLE)
        assertTrue(del.endsWith("[destructive]"))
        assertTrue(del.contains("DELETE /api/3/sites/{id}"))
    }

    @Test
    fun `schema builder handles blank summary and descriptions`() {
        val bare = op("bare", path = "/a/{id}", params = listOf(CatalogParam("id", "path", required = true, schema = buildJsonObject { put("type", "integer") })))
        val desc = InputSchemaBuilder.describe(bare, ApiFamily.CLOUD)
        assertEquals("[Cloud Integrations API v4: GET /a/{id}]", desc)
        val schema = InputSchemaBuilder.build(bare)
        assertEquals("Path parameter.", schema.properties!!["id"]!!.jsonObject["description"]!!.jsonPrimitive.content)
        val withBody = bare.copy(body = CatalogBody("application/json", false, buildJsonObject { put("type", "object"); put("description", "Site.") }))
        assertEquals("Request body (JSON). Site.", InputSchemaBuilder.build(withBody).properties!!["body"]!!.jsonObject["description"]!!.jsonPrimitive.content)
        assertEquals(listOf("id"), InputSchemaBuilder.build(withBody).required)
        val summaryOnly = bare.copy(summary = "Sum", description = "Desc")
        assertTrue(InputSchemaBuilder.describe(summaryOnly, ApiFamily.CLOUD).startsWith("Sum — Desc ["))
        assertTrue(JsonPrimitive(1) is JsonPrimitive)
    }
}
