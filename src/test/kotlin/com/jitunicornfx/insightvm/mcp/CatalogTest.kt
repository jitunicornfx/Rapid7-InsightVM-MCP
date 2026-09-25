package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogBody
import com.jitunicornfx.insightvm.mcp.catalog.CatalogFilter
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogMeta
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogParam
import com.jitunicornfx.insightvm.mcp.catalog.CriteriaField
import com.jitunicornfx.insightvm.mcp.catalog.DiscoveryConnection
import com.jitunicornfx.insightvm.mcp.catalog.InputSchemaBuilder
import com.jitunicornfx.insightvm.mcp.catalog.PagingDefaults
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteria
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteriaMeta
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteriaReference
import com.jitunicornfx.insightvm.mcp.catalog.ToolTextContext
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import com.jitunicornfx.insightvm.mcp.tools.ExportTools
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CatalogTest {

    private companion object {
        /** The operations that return or set an authentication secret, by tool name. */
        val SECRET_TOOLS = setOf(
            "get_two_factor_authentication_key", "regenerate_two_factor_authentication", "set_two_factor_authentication",
            "reset_password", "get_current_shared_secret", "create_shared_secret",
        )
    }

    private val v3 get() = TEST_CATALOGS.getValue(ApiFamily.CONSOLE)
    private val v4 get() = TEST_CATALOGS.getValue(ApiFamily.CLOUD)

    /** Tool text as the default configuration renders it. */
    private val text = ToolTextContext()

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
        assertEquals(182, v3.ops.count { it.readOnly })
        assertEquals(111, v3.ops.count { it.destructive })
        assertEquals(9, v4.ops.count { it.readOnly })
        assertEquals(3, v4.ops.count { it.destructive })
        assertEquals(1, v3.ops.count { it.admin })
        assertEquals(SECRET_TOOLS, v3.ops.filter { it.sensitive }.map { it.name }.toSet())
        assertTrue(v4.ops.none { it.sensitive })
        assertTrue(v4.ops.all { it.name.startsWith("cloud_") })
        assertTrue(v4.ops.none { op -> op.params.any { it.name == "region" } })
        val execute = v3.ops.single { it.admin }
        assertEquals("execute_command", execute.name)
        assertEquals("text/plain", execute.body!!.contentType)
        assertEquals("application/zip", v3.ops.single { it.name == "get_logs" }.responses.success)
        assertTrue(v3.ops.single { it.name == "get_logs" }.responses.binary)
        // The report file is declared as a JSON-labelled `{type: string, format: byte}`: the schema,
        // not the label, makes it binary, and the declared label is kept as written.
        val report = v3.ops.single { it.name == "download_report" }.responses
        assertTrue(report.binary)
        assertEquals("application/json;charset=UTF-8", report.success)
        assertEquals(setOf("get_logs", "download_report"), v3.ops.filter { it.responses.binary }.map { it.name }.toSet())
        assertTrue(v4.ops.none { it.responses.binary })
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
        // Only the listed POST searches may be reads, and they must be: a hand-edited catalog cannot
        // slip a write past --read-only, nor drop a search from it.
        assertTrue(bad(op("create_site", method = "POST", path = "/api/3/sites").copy(readOnly = true)).contains("readOnly"))
        assertTrue(bad(op("find_assets", method = "POST", path = "/api/3/assets/search")).contains("readOnly"))
        assertTrue(bad(op("put_search", method = "PUT", path = "/api/3/assets/search").copy(readOnly = true)).contains("readOnly"))
        CatalogLoader.validate(catalog(ApiFamily.CONSOLE, op("find_assets", method = "POST", path = "/api/3/assets/search").copy(readOnly = true)), ApiFamily.CONSOLE)
        CatalogLoader.validate(catalog(ApiFamily.CLOUD, op("cloud_get_sites", method = "POST", path = "/v4/integration/sites").copy(readOnly = true)), ApiFamily.CLOUD)
        // The secret gate is pinned the same way: a hand-edited catalog can neither clear the flag on
        // one of the listed routes nor set it on any other.
        val idParam = listOf(CatalogParam("id", "path", required = true, schema = JsonObject(emptyMap())))
        val seed = op("get_two_factor_authentication_key", path = "/api/3/users/{id}/2FA", params = idParam)
        assertTrue(bad(seed).contains("sensitive"))
        assertTrue(bad(op("get_current_shared_secret", path = "/api/3/scan_engines/shared_secret")).contains("sensitive"))
        assertTrue(bad(op("get_site").copy(sensitive = true)).contains("sensitive"))
        assertTrue(bad(op("delete_shared_secret", method = "DELETE", path = "/api/3/scan_engines/shared_secret").copy(sensitive = true)).contains("sensitive"))
        CatalogLoader.validate(catalog(ApiFamily.CONSOLE, seed.copy(sensitive = true)), ApiFamily.CONSOLE)
        assertTrue(bad(op("t", path = "/a/{id}")).contains("placeholders"))
        assertTrue(bad(op("t", params = listOf(CatalogParam("id", "path", schema = JsonObject(emptyMap()))))).contains("placeholders"))
        assertTrue(bad(op("h", params = listOf(CatalogParam("x", "header", schema = JsonObject(emptyMap()))))).contains("location"))
        assertTrue(bad(op("b", params = listOf(CatalogParam("body", "query", schema = JsonObject(emptyMap()))))).contains("reserved"))
        assertTrue(bad(op("d", params = listOf(CatalogParam("q", "query", schema = JsonObject(emptyMap())), CatalogParam("q", "query", schema = JsonObject(emptyMap()))))).contains("duplicate parameter"))
        assertTrue(bad(op("s").copy(summary = "<b>x</b>")).contains("markup"))
        assertTrue(bad(op("s").copy(description = "Run <script>alert(1)</script>")).contains("markup"))
        for (opener in listOf("</b", "<!--", "<?x", "<Img")) assertTrue(bad(op("s").copy(description = "a $opener b")).contains("markup"), opener)
        // Comparison operators are the v4 query language, not markup.
        CatalogLoader.validate(catalog(ApiFamily.CONSOLE, op("ok").copy(summary = "a < b", description = "cvss_score >= 9 && risk > 0.0 || a <= b ‹property›")), ApiFamily.CONSOLE)
        assertTrue(bad(op("c").copy(body = CatalogBody("application/xml", true, JsonObject(emptyMap())))).contains("content type"))
        val count = assertFailsWith<IllegalStateException> { CatalogLoader.validate(Catalog(CatalogMeta("console", opCount = 3), listOf(op("a"))), ApiFamily.CONSOLE) }
        assertTrue(count.message!!.contains("opCount"))
        assertFailsWith<IllegalStateException> { CatalogLoader.load(ApiFamily.CONSOLE).let { CatalogLoader.validate(it, ApiFamily.CLOUD) } }
    }

    @Test
    fun `search-criteria reference loader invariants`() {
        val good = SearchCriteriaReference(
            meta = SearchCriteriaMeta(),
            operators = mapOf("is" to mapOf("value" to "string"), "is-applied" to emptyMap()),
            asset = listOf(CriteriaField("risk-score", listOf("is"), listOf("L=Low"))),
            discovery = listOf(DiscoveryConnection("AWS", listOf("aws"), listOf(CriteriaField("region", listOf("is-applied"))))),
        )
        SearchCriteria.validate(good)
        assertEquals(good, SearchCriteria.parse(kotlinx.serialization.json.Json.encodeToString(SearchCriteriaReference.serializer(), good)))
        assertSame(SearchCriteria.bundled, SearchCriteria.bundled, "parsed once per process")

        fun bad(reference: SearchCriteriaReference): String =
            assertFailsWith<IllegalStateException> { SearchCriteria.validate(reference) }.message!!
        assertTrue(bad(good.copy(asset = emptyList())).contains("no asset field"))
        assertTrue(bad(good.copy(discovery = emptyList())).contains("discovery connection"))
        assertTrue(bad(good.copy(discovery = listOf(good.discovery[0].copy(connectionTypes = emptyList())))).contains("discovery connection"))
        assertTrue(bad(good.copy(asset = listOf(CriteriaField("risk score", listOf("is"))))).contains("invalid name 'risk score'"))
        assertTrue(bad(good.copy(asset = listOf(CriteriaField("risk-score", listOf("is<b>"))))).contains("invalid name"))
        assertTrue(bad(good.copy(asset = listOf(CriteriaField("risk-score", emptyList())))).contains("no operator"))
        assertTrue(bad(good.copy(operators = mapOf("is" to mapOf("values" to "string")))).contains("operator property"))
        assertTrue(bad(good.copy(asset = listOf(CriteriaField("risk-score", listOf("is"), listOf("<script>"))))).contains("markup"))
        assertTrue(bad(good.copy(operators = mapOf("is" to mapOf("value" to "<b>string</b>")))).contains("markup"))
        assertFailsWith<IllegalStateException> { SearchCriteria.parse("{not json") }
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
        assertFalse(loud.contains("SECRET"), loud)
        val secrets = CatalogFilter.summarize(emptyList(), cats, ToolFilter(allowSecretTools = true))
        assertTrue(secrets.endsWith("[SECRET TOOLS ENABLED]"), secrets)
        assertFalse(CatalogFilter.summarize(emptyList(), cats, ToolFilter()).contains("["))
    }

    @Test
    fun `read-only keeps the query-only POST searches`() {
        val searches = listOf("find_assets", "sonar_query_search", "cloud_get_sites", "cloud_search_integration_assets", "cloud_search_integration_vulnerabilities")
        val readOnly = CatalogFilter.select(TEST_CATALOGS, ToolFilter(readOnly = true))
        val names = readOnly.map { it.op.name }.toSet()
        for (name in searches) assertTrue(name in names, name)
        // Every console read but the two that return a secret, plus every cloud read.
        assertEquals(182 - 2 + 9, readOnly.size)
        assertTrue(readOnly.all { it.op.readOnly && !it.op.destructive && !it.op.admin && !it.op.sensitive })
        // Without the searches, read-only cloud mode could not list a single site, asset or vulnerability.
        val cloud = CatalogFilter.select(TEST_CATALOGS, ToolFilter(readOnly = true, families = setOf(ApiFamily.CLOUD)))
        assertEquals(9, cloud.size)
        assertTrue(cloud.map { it.op.name }.containsAll(searches.filter { it.startsWith("cloud_") }))
    }

    /**
     * Regression: get_two_factor_authentication_key returns any user's TOTP seed and
     * get_current_shared_secret the engine pairing secret. Both are GETs, so --read-only kept them,
     * and a single injected instruction could pull either into the transcript.
     */
    @Test
    fun `tools that return or set authentication secrets are not registered by default, even under read-only`() {
        fun names(filter: ToolFilter) = CatalogFilter.select(TEST_CATALOGS, filter).map { it.op.name }.toSet()
        for (filter in listOf(ToolFilter(), ToolFilter(readOnly = true), ToolFilter(allowAdminCommands = true))) {
            assertEquals(emptySet(), names(filter) intersect SECRET_TOOLS, filter.toString())
        }
        // A glob naming one does not reach it either: the gate comes before the name filters.
        assertEquals(emptySet(), names(ToolFilter(nameGlobs = listOf("get_two_factor_authentication_key", "*shared_secret"))) intersect SECRET_TOOLS)

        // The explicit opt-in registers all six; with --read-only as well, only the two reads.
        assertEquals(SECRET_TOOLS, names(ToolFilter(allowSecretTools = true)) intersect SECRET_TOOLS)
        assertEquals(
            setOf("get_two_factor_authentication_key", "get_current_shared_secret"),
            names(ToolFilter(readOnly = true, allowSecretTools = true)) intersect SECRET_TOOLS,
        )
        // It opens this gate only: execute_command stays behind its own.
        assertFalse("execute_command" in names(ToolFilter(allowSecretTools = true)))
        assertEquals(343 - 1 - SECRET_TOOLS.size, names(ToolFilter()).size)

        // For the startup warning: globs that match only gated tools (not ones that match nothing).
        assertEquals(
            listOf("*two_factor*", "Reset_Password"),
            CatalogFilter.secretOnlyGlobs(TEST_CATALOGS, listOf("*two_factor*", "*secret*", "get_site", "nothing_*", "Reset_Password")),
        )
    }

    @Test
    fun `glob conversion escapes regex metacharacters`() {
        assertTrue(CatalogFilter.globToRegex("get_*").matches("get_sites"))
        assertFalse(CatalogFilter.globToRegex("get_*").matches("xget_sites"))
        assertTrue(CatalogFilter.globToRegex("a.b").matches("a.b"))
        assertFalse(CatalogFilter.globToRegex("a.b").matches("axb"))
        assertTrue(CatalogFilter.globToRegex("a?c").matches("abc"))
    }

    @Test
    fun `name globs ignore case, as tags already do`() {
        val selected = CatalogFilter.select(TEST_CATALOGS, ToolFilter(nameGlobs = listOf("Get_Site")))
        assertEquals(listOf("get_site"), selected.map { it.op.name })
        assertTrue(CatalogFilter.select(TEST_CATALOGS, ToolFilter(nameGlobs = listOf("CLOUD_*"))).isNotEmpty())
    }

    @Test
    fun `filter values that match nothing are found for the startup warnings`() {
        val cats = mapOf(
            ApiFamily.CONSOLE to catalog(ApiFamily.CONSOLE, op("get_site", tag = "Site"), op("get_user", tag = "User")),
            ApiFamily.CLOUD to catalog(ApiFamily.CLOUD, op("cloud_get_sites", tag = "site"), op("cloud_health", tag = "Health")),
        )
        // Once each, case-insensitively, in a stable order.
        assertEquals(listOf("Health", "Site", "User"), CatalogFilter.tags(cats))
        assertEquals(listOf("Sites", "Userz"), CatalogFilter.unknownTags(cats, listOf("SITE", "Sites", "user", "Userz")))
        assertEquals(listOf("list_*", "x?"), CatalogFilter.unmatchedGlobs(cats, listOf("GET_*", "list_*", "*health", "x?")))
        assertEquals(emptyList(), CatalogFilter.unknownTags(cats, emptyList()))
    }

    // ---------------------------------------------------------------- schema builder

    @Test
    fun `input schema includes params, body and confirm`() {
        val createSite = v3.ops.single { it.name == "create_site" }
        val schema = InputSchemaBuilder.build(createSite, text)
        val props = schema.properties!!
        assertTrue("body" in props)
        assertEquals(listOf("body"), schema.required)
        assertTrue(props["body"]!!.jsonObject["description"]!!.jsonPrimitive.content.startsWith("Request body (JSON)."))
        assertEquals("object", props["body"]!!.jsonObject["type"]!!.jsonPrimitive.content)

        val getAssets = v3.ops.single { it.name == "get_assets" }
        val s2 = InputSchemaBuilder.build(getAssets, text)
        assertNull(s2.required)
        // Parameters are passed through as the catalog has them: the binder routes by name, so a
        // path-or-query hint would change nothing.
        assertEquals(getAssets.params.single { it.name == "sort" }.schema, s2.properties!!["sort"]!!.jsonObject)
        assertEquals("array", s2.properties!!["sort"]!!.jsonObject["type"]!!.jsonPrimitive.content)

        val admin = v3.ops.single { it.admin }
        val s3 = InputSchemaBuilder.build(admin, text)
        assertEquals(listOf("body", "confirm"), s3.required)
        assertEquals("EXECUTE", s3.properties!!["confirm"]!!.jsonObject["enum"]!!.jsonArray.single().jsonPrimitive.content)
        assertTrue(s3.properties!!["body"]!!.jsonObject["description"]!!.jsonPrimitive.content.startsWith("Request body (text/plain)."))

        val desc = InputSchemaBuilder.describe(admin, ApiFamily.CONSOLE, text)
        assertTrue(desc.contains("[ADMIN:"))
        val del = InputSchemaBuilder.describe(v3.ops.single { it.name == "delete_site" }, ApiFamily.CONSOLE, text)
        assertTrue(del.endsWith("[v3 DELETE /api/3/sites/{id}] [destructive]"), del)
    }

    @Test
    fun `schema builder handles blank summary and descriptions`() {
        val bare = op("bare", path = "/a/{id}", params = listOf(CatalogParam("id", "path", required = true, schema = buildJsonObject { put("type", "integer") })))
        val desc = InputSchemaBuilder.describe(bare, ApiFamily.CLOUD, text)
        assertEquals("[v4 GET /a/{id}]", desc)
        val schema = InputSchemaBuilder.build(bare, text)
        assertEquals(buildJsonObject { put("type", "integer") }, schema.properties!!["id"]!!.jsonObject, "no description is invented")
        val withBody = bare.copy(body = CatalogBody("application/json", false, buildJsonObject { put("type", "object"); put("description", "Site.") }))
        assertEquals("Request body (JSON). Site.", InputSchemaBuilder.build(withBody, text).properties!!["body"]!!.jsonObject["description"]!!.jsonPrimitive.content)
        assertEquals(listOf("id"), InputSchemaBuilder.build(withBody, text).required)
        val summaryOnly = bare.copy(summary = "Sum", description = "Desc")
        assertTrue(InputSchemaBuilder.describe(summaryOnly, ApiFamily.CLOUD, text).startsWith("Sum — Desc ["))
        assertTrue(JsonPrimitive(1) is JsonPrimitive)
    }

    @Test
    fun `paging text states only what the configured server does`() {
        fun size(schema: JsonObject) = CatalogParam("size", "query", schema = schema)
        val paged = op("paged", params = listOf(size(buildJsonObject { put("type", "integer"); put("default", 10); put("maximum", 50) })))

        // The specification's own maximum wins over the configured default, in the text and the schema alike.
        val guidance = InputSchemaBuilder.pagingGuidance(paged, ApiFamily.CONSOLE, ToolTextContext(defaultPageSize = 100))
        assertTrue(guidance.startsWith(" Paged: 'size' defaults to 50 and is clamped to 50. For a COUNT ONLY, call with size=1 and read page.totalResources —"), guidance)
        val sizeSchema = InputSchemaBuilder.build(paged, ToolTextContext(defaultPageSize = 100)).properties!!["size"]!!.jsonObject
        assertEquals(listOf("type", "default", "maximum", "description"), sizeSchema.keys.toList())
        assertEquals("50", sizeSchema["default"]!!.jsonPrimitive.content)
        assertEquals("Defaults to 50 on this server; values above 50 are clamped so a page can fit the response budget.", sizeSchema["description"]!!.jsonPrimitive.content)
        assertEquals(50, PagingDefaults.apply(paged, JsonObject(emptyMap()), default = 100)["size"]!!.jsonPrimitive.content.toInt(), "and the server agrees")

        // Every configurable sentence can drop out; with none left there is no "Paged:" stub.
        val cursorOnly = op("cursor_only", params = listOf(CatalogParam("cursor", "query", schema = buildJsonObject { put("type", "string") })))
        assertTrue(InputSchemaBuilder.pagingGuidance(cursorOnly, ApiFamily.CLOUD, ToolTextContext()).contains(ExportTools.EXPORT_TOOL))
        assertEquals("", InputSchemaBuilder.pagingGuidance(cursorOnly, ApiFamily.CLOUD, ToolTextContext(exportEnabled = false, keepRecordLinks = true)))
        assertEquals("[v4 GET /x]", InputSchemaBuilder.describe(cursorOnly, ApiFamily.CLOUD, ToolTextContext(exportEnabled = false, keepRecordLinks = true)))

        // A paged operation the export tool would refuse is never pointed at it.
        val pagedWrite = op("paged_write", method = "POST", params = paged.params)
        assertFalse(InputSchemaBuilder.pagingGuidance(pagedWrite, ApiFamily.CONSOLE, ToolTextContext()).contains(ExportTools.EXPORT_TOOL))
    }

    @Test
    fun `tool text context follows the configuration`() {
        val config = testConfig().copy(defaultPageSize = 25, keepRecordLinks = true)
        assertEquals(ToolTextContext(defaultPageSize = 25, exportEnabled = true, keepRecordLinks = true), ToolTextContext.of(config))
        assertFalse(ToolTextContext.of(config.copy(exportDisabled = true)).exportEnabled)
        assertFalse(ToolTextContext.of(config.copy(filter = ToolFilter(readOnly = true))).exportEnabled)
    }
}
