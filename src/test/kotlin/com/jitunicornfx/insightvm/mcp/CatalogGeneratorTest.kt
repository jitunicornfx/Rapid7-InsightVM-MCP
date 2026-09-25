package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogGenerator
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.catalog.CatalogResponses
import com.jitunicornfx.insightvm.mcp.catalog.CriteriaField
import com.jitunicornfx.insightvm.mcp.catalog.DiscoveryConnection
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteria
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteriaMeta
import com.jitunicornfx.insightvm.mcp.catalog.SearchCriteriaTables
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CatalogGeneratorTest {

    private val specs: Path = Path.of("specs")
    private val committed: Path = Path.of("src/main/resources/catalog")

    /** The OpenAPI documents are not committed; spec-backed tests are skipped where they are absent. */
    private fun requireSpecs() = org.junit.jupiter.api.Assumptions.assumeTrue(Files.isDirectory(specs), "specs/ not present")

    @Test
    fun `generated catalogs are byte-identical to the committed ones`() {
        requireSpecs()
        assertEquals(emptyList(), CatalogGenerator.drift(specs, committed))
    }

    @Test
    fun `generated catalogs pass the runtime loader and match the bundled resources`() {
        requireSpecs()
        val generated = CatalogGenerator.generate(specs)
        for (src in CatalogGenerator.SOURCES) {
            val parsed = CatalogLoader.parse(generated.getValue(src.outputFile), src.family)
            val bundled = CatalogLoader.load(src.family)
            assertEquals(bundled.ops, parsed.ops)
            assertEquals(bundled.meta.copy(generator = ""), parsed.meta.copy(generator = ""))
        }
        assertEquals(330, CatalogLoader.parse(generated.getValue("v3.json"), ApiFamily.CONSOLE).ops.size)
        assertEquals(13, CatalogLoader.parse(generated.getValue("v4.json"), ApiFamily.CLOUD).ops.size)
        assertEquals(SearchCriteria.load(), SearchCriteria.parse(generated.getValue(CatalogGenerator.SEARCH_CRITERIA_FILE)))
        assertEquals("specs/insightvm-console-v3.json", SearchCriteria.load().meta.generatedFrom)
    }

    @Test
    fun `write and drift round-trip through a directory`() {
        requireSpecs()
        val dir = createTempDirectory("catalog-out")
        try {
            assertEquals(listOf("v3.json", "v4.json", "search-criteria.json"), CatalogGenerator.drift(specs, dir))
            assertEquals(CatalogGenerator.OUTPUTS, CatalogGenerator.drift(specs, dir))
            val written = CatalogGenerator.write(specs, dir)
            assertEquals(3, written.size)
            assertTrue(written.all { Files.size(it) > 1000 })
            assertEquals(emptyList(), CatalogGenerator.drift(specs, dir))
            Files.writeString(dir.resolve("v4.json"), "{}")
            Files.writeString(dir.resolve("search-criteria.json"), "{}")
            assertEquals(listOf("v4.json", "search-criteria.json"), CatalogGenerator.drift(specs, dir))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `text cleaning`() {
        assertEquals("", CatalogGenerator.cleanText(null))
        assertEquals("", CatalogGenerator.cleanText(""))
        assertEquals("A & B ‹x› ✓ |", CatalogGenerator.cleanText("<p>A &amp; B</p> &lt;x&gt; &check; &#124;"))
        assertEquals("a b", CatalogGenerator.cleanText("a \t\n  b"))
        assertEquals("abc…", CatalogGenerator.cleanText("abcdef", limit = 4))
        assertEquals("AB", CatalogGenerator.unescapeEntities("&#x41;&#66;"))
        assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.unescapeEntities("&bogus;") }
    }

    @Test
    fun `text cleaning strips only layout tags and keeps comparison operators`() {
        // Layout tags go; a placeholder such as <property> is prose and stays, neutralised.
        assertEquals("a >= b x ‹property›[,ASC]", CatalogGenerator.cleanText("a >= b <strong>x</strong> <property>[,ASC]"))
        assertEquals("cvss_score >= 9 && risk > 0.0 || a <= b", CatalogGenerator.cleanText("cvss_score &gt;= 9 &amp;&amp; risk > 0.0 || a &lt;= b"))
        assertEquals("‹host›:‹port› ‹int32›", CatalogGenerator.cleanText("<host>:<port> &lt;int32&gt;"))
        // Anything that could still open markup is neutralised, closed or not.
        assertEquals("‹script›x‹/script› ‹!-- c --› 1 < 2 ‹b ‹?x",CatalogGenerator.cleanText("&lt;script&gt;x&lt;/script&gt; <!-- c --> 1 < 2 <b <?x"))
        for (tag in listOf("a href=\"#x\"", "b", "br/", "code", "div class=\"p\"", "em", "i", "li", "ol", "p", "pre", "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul")) {
            assertEquals("x y", CatalogGenerator.cleanText("x<$tag>y"), tag)
        }
        assertEquals("‹id› ‹abbr›", CatalogGenerator.cleanText("<id> <abbr>"), "only whole allow-listed names are stripped")
        // v4 descriptions that are only unrendered template keys carry no text.
        assertEquals("", CatalogGenerator.cleanText("\${scan.id.description}, \${scanid.id.description}"))
        assertEquals("Uses \${x} inline.", CatalogGenerator.cleanText("Uses \${x} inline."))
    }

    /**
     * Regression: the specs link their search-criteria reference, which lives in info.description
     * where no tool can carry it. Stripped of its tag the link read "See Search Criteria for more
     * information", and the model had nowhere to look.
     */
    @Test
    fun `text cleaning points the specs' search-criteria links at the reference tool`() {
        val pointer = "Call insightvm_search_criteria for the operators each field accepts and the value each operator takes."
        assertEquals(pointer, CatalogGenerator.ASSET_CRITERIA_POINTER)
        assertEquals(
            "Filters used to match assets. $pointer",
            CatalogGenerator.cleanText("Filters used to match assets. See <a href=\"#section/Responses/SearchCriteria\">Search Criteria</a> for more information on the structure and format."),
        )
        assertEquals(
            "Static groups do not. $pointer",
            CatalogGenerator.cleanText("Static groups do not. \nSee the <a href=\"#section/Responses/SearchCriteria\">Search Criteria</a> for more information on using dynamic criteria."),
        )
        assertEquals(
            "From a connection. ${CatalogGenerator.DISCOVERY_CRITERIA_POINTER}",
            CatalogGenerator.cleanText("From a connection. See <a href=\"#section/Responses/DiscoverySearchCriteria\">Discovery Connection Search Criteria</a> for more information on the structure and format."),
        )
        assertContains(CatalogGenerator.DISCOVERY_CRITERIA_POINTER, "kind \"discovery\"")
        // Any other in-page link is only a tag, and is stripped as before.
        assertEquals("See Asset Search resource.", CatalogGenerator.cleanText("See <a href=\"#operation/findAssets\">Asset Search</a> resource."))
    }

    @Test
    fun `snake case`() {
        assertEquals("get_site_scan_schedules", CatalogGenerator.snakeCase("getSiteScanSchedules"))
        assertEquals("get_vulnerability_references_1", CatalogGenerator.snakeCase("getVulnerabilityReferences_1"))
        assertEquals("start_http_scan", CatalogGenerator.snakeCase("startHTTPScan"))
        assertEquals("a_b", CatalogGenerator.snakeCase("__a--b__"))
    }

    private fun spec(paths: JsonObject, schemas: JsonObject = JsonObject(emptyMap()), info: String? = null): JsonObject = buildJsonObject {
        putJsonObject("info") { put("title", "T"); put("version", "9"); info?.let { put("description", it) } }
        put("paths", paths)
        putJsonObject("components") { put("schemas", schemas) }
    }

    // ---------------------------------------------------------------- search criteria

    /**
     * A small introduction laid out as the v3 one is: an anchor after some headings, a fenced block
     * holding a `#` line, stray spaces inside backticks, three ways of writing enumerated values,
     * operator names that differ between the tables, and discovery tables per connection type.
     */
    private val criteriaIntro = """
        # Overview
        Intro.
        #### Search Criteria <a section="section/Responses/SearchCriteria"></a>
        ```json
        { "field": "<field-name>" }
        # not a heading inside a fence
        ```
        ##### Fields
        | Field          | Operators                              |
        | -------------- | -------------------------------------- |
        | `risk-score`   | `is` ` in-range` `is-less-than`        |
        | `host-type`    | `in` `does-not-include`                |
        ##### Enumerated Properties
        | Field        | Acceptable Values                                                            |
        | ------------ | ---------------------------------------------------------------------------- |
        | `host-type`  | 0=Unknown, 1=Guest                                                           |
        | `risk-score` | <ul><li><code>L</code> = Low</li><li><code>H</code> = High</li></ul>         |
        ##### Operator Properties <a section="section/Responses/SearchCriteria/OperatorProperties"></a>
        | Operator     | `value`            | `lower`    | `upper`    |
        | -------------|--------------------|------------|------------|
        | `is`         | `string`           |            |            |
        | `in`         | `Array[ string ]`  |            |            |
        | `in-range`   |                    | `numeric`  | `numeric`  |
        | `less-than`  | `numeric` (days)   |            |            |
        #### Discovery Connection Search Criteria <a section="section/Responses/DiscoverySearchCriteria"></a>
        ##### Fields (AWS)
        Connections of the type `"aws"`.
        | Field       | Operators |
        | ----------- | --------- |
        | `region`    | `in`      |
        | `vm-state`  | `is`      |
        ##### Fields (Sonar)
        Connections of the type `"sonar"`.
        | Field           | Operators |
        | --------------- | --------- |
        | `search-domain` | `is`      |
        ##### Enumerated Properties (AWS)
        | Field      | Acceptable Values |
        | ---------- | ----------------- |
        | `vm-state` | `on` `off`        |
        ## HATEOAS
        Links.
    """.trimIndent()

    private fun parseCriteria(intro: String) = CatalogGenerator.searchCriteria(spec(JsonObject(emptyMap()), info = intro), "sha", "specs/x.json")

    /** [criteriaIntro] with [from] replaced; fails if [from] is not there, so no case passes vacuously. */
    private fun criteriaIntro(from: String, to: String): String {
        assertContains(criteriaIntro, from)
        return criteriaIntro.replace(from, to)
    }

    @Test
    fun `search criteria - the introduction's tables are read into the reference`() {
        val ref = assertNotNull(parseCriteria(criteriaIntro))
        assertEquals(SearchCriteriaMeta("sha", CatalogGenerator.GENERATOR_VERSION, "specs/x.json"), ref.meta)
        assertEquals(
            listOf(
                CriteriaField("risk-score", listOf("is", "in-range", "is-less-than"), listOf("L=Low", "H=High")),
                CriteriaField("host-type", listOf("in", "does-not-include"), listOf("0=Unknown", "1=Guest")),
            ),
            ref.asset,
        )
        // Names are aliased to the field tables' spelling; types are kept as written, brackets tidied. An
        // array the table lists under `value` is the filter schema's `values` — see SearchCriteriaTables.
        assertEquals(
            mapOf(
                "is" to mapOf("value" to "string"),
                "in" to mapOf("values" to "Array[string]"),
                "in-range" to mapOf("lower" to "numeric", "upper" to "numeric"),
                "is-less-than" to mapOf("value" to "numeric (days)"),
            ),
            ref.operators,
        )
        assertEquals(
            listOf(
                DiscoveryConnection("AWS", listOf("aws"), listOf(CriteriaField("region", listOf("in")), CriteriaField("vm-state", listOf("is"), listOf("on", "off")))),
                DiscoveryConnection("Sonar", listOf("sonar"), listOf(CriteriaField("search-domain", listOf("is")))),
            ),
            ref.discovery,
        )
        // A heading's trailing anchor is not part of its title, and a '#' line inside a fence is no heading.
        assertEquals(
            listOf(
                "Overview", "Search Criteria", "Fields", "Enumerated Properties", "Operator Properties",
                "Discovery Connection Search Criteria", "Fields (AWS)", "Fields (Sonar)", "Enumerated Properties (AWS)", "HATEOAS",
            ),
            SearchCriteriaTables.sections(criteriaIntro).map { it.title },
        )
        assertEquals(listOf(1, 4, 5, 5, 5, 4, 5, 5, 5, 2), SearchCriteriaTables.sections(criteriaIntro).map { it.level })
        // No asset fields table, no reference: the v4 introduction, and every other test's spec.
        assertNull(parseCriteria("# Overview\n## Search Criteria\nUse expressions."))
        assertNull(CatalogGenerator.searchCriteria(spec(JsonObject(emptyMap())), "s", "f"))
    }

    /** Regression guard: an operator the tables name that no alias maps must stop the build, not vanish. */
    @Test
    fun `search criteria - an unexpected table fails generation rather than being half-read`() {
        fun fails(intro: String, message: String) {
            val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> { parseCriteria(intro) }
            assertContains(e.message!!, message)
        }
        fails(criteriaIntro("| `less-than`", "| `lesser-than`"), "'lesser-than', which no field table uses and no alias maps")
        fails(criteriaIntro("| Operator     |", "| Name         |"), "has columns")
        fails(criteriaIntro("| `risk-score`   | `is`", "| `risk-score` x | `is`"), "text outside backticks")
        fails(criteriaIntro("| `host-type`    | `in`", "| `risk-score`   | `in`"), "lists risk-score twice")
        fails(criteriaIntro("| `host-type`    | `in` `does-not-include`", "| `host-type`    | `in` `in`"), "repeats a name")
        fails(criteriaIntro("| `host-type`    | `in` `does-not-include`", "| `host type`    | `in`"), "invalid name 'host type'")
        fails(criteriaIntro("| `host-type`  | 0=Unknown", "| `host-kind`  | 0=Unknown"), "lists values for 'host-kind'")
        fails(criteriaIntro("| `host-type`  | 0=Unknown, 1=Guest", "| `host-type`  | 0=Unknown, ,1=Guest"), "empty value")
        fails(criteriaIntro("##### Operator Properties", "##### Operators"), "no 'Operator Properties' section")
        fails(criteriaIntro("##### Enumerated Properties\n", "##### Values\n"), "no 'Enumerated Properties' section")
        fails(criteriaIntro("##### Fields (AWS)", "##### AWS").replace("##### Fields (Sonar)", "##### Sonar"), "no discovery")
        fails(criteriaIntro("##### Enumerated Properties (AWS)", "##### Enumerated Properties (Azure)"), "names no discovery connection")
        fails(criteriaIntro("Connections of the type `\"sonar\"`.", "Sonar connections."), "'Fields (Sonar)' names no connection type")
        fails(criteriaIntro("| `in-range`   |                    | `numeric`  | `numeric`  |", "| `in-range`   | `x` |"), "row of 2 cells")
        fails(criteriaIntro("| ----------- | --------- |", "| nothing |"), "no markdown table")
        fails(criteriaIntro("##### Fields (Sonar)", "##### Fields"), "2 sections are titled 'Fields'")
        // An alias may land on a name the table also lists, but only with the same properties.
        fails(criteriaIntro("| `is`         | `string`           |", "| `is`         | `string`           |            |            |\n| `not-contains` | `string` |"), "no field table uses")
        val merged = criteriaIntro("`is` ` in-range`", "`is` `does-not-contain` ` in-range`")
        assertEquals(
            mapOf("value" to "string"),
            parseCriteria(merged.replace("| `is`         | `string`           |            |            |", "| `does-not-contain` | `string` | | |\n| `not-contains` | `string` | | |"))!!.operators["does-not-contain"],
        )
        fails(
            merged.replace("| `is`         | `string`           |            |            |", "| `does-not-contain` | `string` | | |\n| `not-contains` | `numeric` | | |"),
            "gives does-not-contain two different sets of properties",
        )
        assertEquals(mapOf("ends with" to "ends-with", "less-than" to "is-less-than", "like" to "is-like", "not-contains" to "does-not-contain"), SearchCriteriaTables.OPERATOR_ALIASES)
    }

    private fun criteriaSchemas(withDiscovery: Boolean = true) = buildJsonObject {
        fun link(discovery: Boolean) = if (discovery) {
            "Filters from a connection. See <a href=\"#section/Responses/DiscoverySearchCriteria\">Discovery Connection Search Criteria</a> for more information on the structure and format."
        } else {
            "Filters used to match assets. See <a href=\"#section/Responses/SearchCriteria\">Search Criteria</a> for more information on the structure and format."
        }
        for ((holder, filter) in listOf("SearchCriteria" to "SwaggerSearchCriteriaFilter", "DiscoverySearchCriteria" to "SwaggerDiscoverySearchCriteriaFilter")) {
            val discovery = holder.startsWith("Discovery")
            putJsonObject(holder) {
                putJsonObject("properties") {
                    putJsonObject("filters") { put("type", "array"); put("description", link(discovery)); putJsonObject("items") { put("\$ref", "#/components/schemas/$filter") } }
                    putJsonObject("match") { put("type", "string"); putJsonArray("enum") { add(JsonPrimitive("all")); add(JsonPrimitive("any")) } }
                }
            }
            if (discovery && !withDiscovery) continue
            putJsonObject(filter) {
                put("description", link(discovery))
                putJsonObject("properties") {
                    putJsonObject("field") { put("type", "string"); put("description", "The filter field for the search criteria.") }
                    putJsonObject("lower") { put("type", "object"); put("description", "The lower value to match in a range criteria.") }
                    putJsonObject("operator") { put("type", "string"); put("description", "The operator on how to match the search criteria.") }
                    putJsonObject("upper") { put("type", "object") }
                    putJsonObject("value") { put("type", "object"); put("description", "The single value to match using the operator.") }
                    putJsonObject("values") {
                        put("type", "array"); put("description", "An array of values to match using the operator.")
                        putJsonObject("items") { put("type", "object"); put("description", "An array of values to match using the operator.") }
                    }
                }
            }
        }
    }

    private val criteriaPaths = buildJsonObject {
        for ((path, opId, schema) in listOf(
            Triple("/api/3/assets/search", "findAssets", "SearchCriteria"),
            Triple("/api/3/sites/discovery", "setSiteDiscoverySearchCriteria", "DiscoverySearchCriteria"),
        )) {
            putJsonObject(path) {
                putJsonObject("post") {
                    put("operationId", opId)
                    putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/$schema") } } } }
                }
            }
        }
    }

    /**
     * Regression: the eight search-criteria bodies offered `field` and `operator` as free text and
     * typed `value`, `lower` and `upper` as `object`, which no operator takes.
     */
    @Test
    fun `build rules - the search-criteria reference constrains the filter schemas`() {
        val bodies = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(criteriaPaths, criteriaSchemas(), criteriaIntro), "s", "f")
            .ops.associate { it.opId to it.body!!.schema }
        fun enumOf(filter: JsonObject, property: String) = filter.at("properties", property)["enum"]!!.jsonArray.map { it.jsonPrimitive.content }

        val filters = bodies.getValue("findAssets").at("properties", "filters")
        assertEquals("Filters used to match assets. ${CatalogGenerator.ASSET_CRITERIA_POINTER}", filters.str("description"))
        val asset = filters.at("items")
        assertEquals(listOf("risk-score", "host-type"), enumOf(asset, "field"))
        assertEquals(listOf("is", "in-range", "is-less-than", "in", "does-not-include"), enumOf(asset, "operator"))
        assertEquals("string", asset.at("properties", "field").str("type"))
        assertEquals(
            buildJsonObject { put("description", "The single value to match using the operator. A string or number, depending on the operator.") },
            asset.at("properties", "value"),
        )
        assertEquals(
            "An array of values to match using the operator. Used by the operators that take a list: in.",
            asset.at("properties", "values").str("description"),
            "the schema's own array property, named for the operators that read it",
        )
        assertEquals(buildJsonObject { put("description", "The lower value to match in a range criteria. A string or number, depending on the operator.") }, asset.at("properties", "lower"))
        assertEquals(buildJsonObject { put("description", "A string or number, depending on the operator.") }, asset.at("properties", "upper"))
        assertEquals(JsonObject(emptyMap()), asset.at("properties", "values", "items"), "an untyped item whose text repeats its array's")
        assertEquals("array", asset.at("properties", "values").str("type"))

        val discovery = bodies.getValue("setSiteDiscoverySearchCriteria").at("properties", "filters")
        assertEquals("Filters from a connection. ${CatalogGenerator.DISCOVERY_CRITERIA_POINTER}", discovery.str("description"))
        assertEquals(listOf("region", "vm-state", "search-domain"), enumOf(discovery.at("items"), "field"))
        assertEquals(listOf("in", "is"), enumOf(discovery.at("items"), "operator"))

        // Without the reference the same components pass through as declared.
        val plain = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(criteriaPaths, criteriaSchemas()), "s", "f").ops.first { it.opId == "findAssets" }
        val bare = plain.body!!.schema.at("properties", "filters", "items", "properties")
        assertNull(bare.at("field")["enum"])
        assertEquals("object", bare.at("value").str("type"))

        // With the reference, a filter component it cannot apply to fails the build.
        val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> {
            CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(criteriaPaths, criteriaSchemas(withDiscovery = false), criteriaIntro), "s", "f")
        }
        assertContains(e.message!!, "SwaggerDiscoverySearchCriteriaFilter")
        val noValues = buildJsonObject {
            criteriaSchemas().forEach { (name, schema) ->
                if (name != "SwaggerSearchCriteriaFilter") put(name, schema)
                else put(name, JsonObject(schema.jsonObject + ("properties" to JsonObject(schema.jsonObject.at("properties") - "values"))))
            }
        }
        val missing = assertFailsWith<CatalogGenerator.CatalogGenerationException> {
            CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(criteriaPaths, noValues, criteriaIntro), "s", "f")
        }
        assertContains(missing.message!!, "SwaggerSearchCriteriaFilter has no 'values' property")
    }

    /**
     * Regression: updateTagSearchCriteria's description is a 5,900-character copy of the criteria
     * tables, which the 600-character cap cut mid-row with nothing to say so.
     */
    @Test
    fun `build rules - a description the cap would gut fails, and a copy of the criteria tables is replaced`() {
        fun op(method: String, path: String, opId: String, description: String) = buildJsonObject {
            putJsonObject(path) { putJsonObject(method) { put("operationId", opId); put("description", description) } }
        }
        val tables = "Updates the search criteria associated with the tag. \n\nThe following table: \n| Field | Operators |\n" + "| ip-address | is |\n".repeat(400)
        val tag = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(op("put", "/api/3/tags/{id}/search_criteria", "updateTagSearchCriteria", tables)), "s", "f").ops.single()
        assertEquals("Updates the search criteria associated with the tag. ${CatalogGenerator.ASSET_CRITERIA_POINTER}", tag.description)

        // The cap keeps 599 characters and an ellipsis; losing up to MAX_DESCRIPTION_CUT beyond that is a tail.
        val limit = CatalogGenerator.MAX_DESCRIPTION - 1 + CatalogGenerator.MAX_DESCRIPTION_CUT
        val tail = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(op("get", "/api/3/x", "getX", "y".repeat(limit))), "s", "f").ops.single()
        assertEquals(CatalogGenerator.MAX_DESCRIPTION, tail.description.length)
        assertTrue(tail.description.endsWith("…"))
        val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> {
            CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(op("get", "/api/3/x", "getX", "y".repeat(limit + 1))), "s", "f")
        }
        assertContains(e.message!!, "the description of \"getX\" is ${limit + 1} characters")
        assertContains(e.message!!, "drop ${CatalogGenerator.MAX_DESCRIPTION_CUT + 1} of them")
    }

    /** Regression: v4's "Search Criteria" section, the only place it explains the two chunks, never reached a tool. */
    @Test
    fun `build rules - the v4 search-criteria section is added to the asset search body only`() {
        val intro = "# Overview\nx\n## Sorting\ns\n## Search Criteria\n\nUse search criteria.\n" +
            "- A `vulnerability` chunk by itself does not change the number of assets returned.\n" +
            "- `{\"asset\": \"risk > 0.0\", \"vulnerability\": \"cvss_score >= 9\"}`\n\n## Responses\nr\n"
        val note = "Use search criteria. - A `vulnerability` chunk by itself does not change the number of assets returned. " +
            "- `{\"asset\": \"risk > 0.0\", \"vulnerability\": \"cvss_score >= 9\"}`"
        val paths = buildJsonObject {
            for ((path, description) in listOf("/v4/integration/assets" to null, "/v4/integration/vulnerabilities" to "Criteria for searching vulnerabilities.", "/v4/integration/sites" to "Site criteria.")) {
                putJsonObject(path) {
                    putJsonObject("post") {
                        put("operationId", "search${path.substringAfterLast('/')}")
                        putJsonObject("requestBody") {
                            putJsonObject("content") {
                                putJsonObject("application/json") { putJsonObject("schema") { put("type", "object"); description?.let { put("description", it) } } }
                            }
                        }
                    }
                }
            }
        }
        val bodies = CatalogGenerator.buildCatalog(ApiFamily.CLOUD, spec(paths, info = intro), "s", "f").ops.associate { it.path to it.body!!.schema.str("description") }
        assertEquals(note, bodies["/v4/integration/assets"])
        // The section is about the asset search's two chunks and its examples send {"asset": ...}; the
        // vulnerabilities search has a vulnerability chunk alone, so it keeps its own text.
        assertEquals("Criteria for searching vulnerabilities.", bodies["/v4/integration/vulnerabilities"])
        assertEquals("Site criteria.", bodies["/v4/integration/sites"], "only the asset search")
        // Without the section, nothing is added.
        assertNull(CatalogGenerator.buildCatalog(ApiFamily.CLOUD, spec(paths), "s", "f").ops.first { it.path == "/v4/integration/assets" }.body!!.schema.str("description"))
    }

    @Test
    fun `build rules - flags, params, refs, bodies and responses`() {
        val schemas = buildJsonObject {
            putJsonObject("Node") {
                put("type", "object")
                putJsonArray("required") { add(JsonPrimitive("id")); add(JsonPrimitive("name")) }
                putJsonObject("properties") {
                    putJsonObject("id") { put("type", "integer"); put("readOnly", true) }
                    putJsonObject("name") { put("type", "string"); put("description", "<b>The</b> name"); put("example", "x") }
                    putJsonObject("child") { put("\$ref", "#/components/schemas/Node") }
                    putJsonObject("items") { put("type", "array"); putJsonObject("items") { put("\$ref", "#/components/schemas/Leaf") } }
                    putJsonObject("extra") { put("additionalProperties", buildJsonObject { put("\$ref", "#/components/schemas/Leaf") }) }
                    putJsonObject("any") { putJsonArray("oneOf") { add(buildJsonObject { put("\$ref", "#/components/schemas/Leaf") }) } }
                    putJsonObject("kid") { put("\$ref", "#/components/schemas/Leaf"); put("description", "<b>Kid</b> &lt;x&gt;") }
                }
            }
            putJsonObject("Leaf") { put("type", "string"); put("title", "Leaf"); put("xml", buildJsonObject { }) }
        }
        val paths = buildJsonObject {
            putJsonObject("/api/3/things/{id}") {
                putJsonObject("delete") {
                    put("operationId", "removeThing")
                    putJsonArray("tags") { add(JsonPrimitive("Thing")) }
                    put("summary", "Remove")
                    putJsonArray("parameters") {
                        add(buildJsonObject { put("name", "id"); put("in", "path"); put("schema", buildJsonObject { put("format", "int32") }) })
                        add(buildJsonObject { put("name", "sort"); put("in", "query"); put("schema", buildJsonObject { put("type", "array"); putJsonArray("enum") { add(JsonPrimitive("a")) } }) })
                        add(buildJsonObject { put("name", "flag"); put("in", "query"); put("schema", buildJsonObject { put("default", false) }) })
                        add(buildJsonObject { put("name", "n"); put("in", "query"); put("schema", buildJsonObject { put("default", 5) }) })
                        add(buildJsonObject { put("name", "hdr"); put("in", "header"); put("schema", buildJsonObject { }) })
                    }
                    putJsonObject("responses") { putJsonObject("200") { putJsonObject("content") { putJsonObject("application/json;charset=UTF-8") { } } } }
                }
                putJsonObject("put") {
                    put("operationId", "updateThing")
                    putJsonObject("requestBody") {
                        put("required", true)
                        putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/Node") } } }
                    }
                    putJsonObject("responses") { putJsonObject("202") { } }
                }
            }
            putJsonObject("/api/3/administration/commands") {
                putJsonObject("post") {
                    put("operationId", "executeCommand")
                    putJsonObject("requestBody") { put("description", "cmd"); putJsonObject("content") { putJsonObject("text/plain") { } } }
                    putJsonObject("responses") { putJsonObject("200") { putJsonObject("content") { putJsonObject("text/plain") { } } } }
                }
            }
            putJsonObject("/api/3/logs") {
                putJsonObject("get") {
                    put("operationId", "getLogs")
                    putJsonObject("responses") { putJsonObject("200") { putJsonObject("content") { putJsonObject("application/zip") { } } } }
                }
            }
        }
        val cat = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(paths, schemas), "sha", "specs/x.json")
        assertEquals(listOf("execute_command", "get_logs", "remove_thing", "update_thing"), cat.ops.map { it.name })
        assertEquals("T", cat.meta.title); assertEquals("9", cat.meta.specVersion); assertEquals(4, cat.meta.opCount)

        val remove = cat.ops.single { it.name == "remove_thing" }
        assertTrue(remove.destructive); assertTrue(!remove.readOnly); assertEquals("Thing", remove.tag); assertEquals("Remove", remove.summary)
        assertEquals(listOf("id", "sort", "flag", "n"), remove.params.map { it.name })
        assertEquals("integer", remove.params[0].schema["type"]!!.jsonPrimitive.content)
        assertTrue(remove.params[0].required)
        val sort = remove.params[1]
        assertTrue(sort.array)
        assertEquals("a", sort.schema["items"]!!.jsonObject["enum"]!!.let { (it as kotlinx.serialization.json.JsonArray).single().jsonPrimitive.content })
        assertEquals("boolean", remove.params[2].schema["type"]!!.jsonPrimitive.content)
        assertEquals("integer", remove.params[3].schema["type"]!!.jsonPrimitive.content)
        assertEquals("application/json", remove.responses.success)

        val update = cat.ops.single { it.name == "update_thing" }
        assertEquals("none", update.responses.success)
        val body = update.body!!
        assertTrue(body.required)
        val props = body.schema["properties"]!!.jsonObject
        assertTrue("id" !in props, "readOnly property dropped")
        assertEquals(listOf("name"), (body.schema["required"] as kotlinx.serialization.json.JsonArray).map { it.jsonPrimitive.content })
        assertEquals("The name", props["name"]!!.jsonObject["description"]!!.jsonPrimitive.content)
        assertTrue("example" !in props["name"]!!.jsonObject)
        assertTrue(props["child"]!!.jsonObject["description"]!!.jsonPrimitive.content.contains("nested object"), "cycle replaced")
        assertEquals("string", props["items"]!!.jsonObject["items"]!!.jsonObject["type"]!!.jsonPrimitive.content)
        assertTrue("title" !in props["items"]!!.jsonObject["items"]!!.jsonObject)
        assertEquals("string", props["extra"]!!.jsonObject["additionalProperties"]!!.jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals("string", (props["any"]!!.jsonObject["oneOf"] as kotlinx.serialization.json.JsonArray).single().jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals("Kid ‹x›", props["kid"]!!.jsonObject["description"]!!.jsonPrimitive.content, "a description beside a \$ref is cleaned like any other")

        val admin = cat.ops.single { it.name == "execute_command" }
        assertTrue(admin.admin); assertEquals("text/plain", admin.body!!.contentType); assertEquals("cmd", admin.body!!.schema["description"]!!.jsonPrimitive.content)
        assertEquals("text/plain", admin.responses.success)
        val logs = cat.ops.single { it.name == "get_logs" }
        assertTrue(logs.responses.binary); assertEquals("application/zip", logs.responses.success); assertTrue(logs.readOnly)
    }

    /**
     * Regression: downloadReport declares its report, usually GZip, as `application/json;charset=UTF-8`
     * with `{type: string, format: byte}`. Only the label was read, so it was catalogued as JSON text.
     */
    @Test
    fun `build rules - a file-shaped success body is binary whatever its label`() {
        fun response(ct: String, schema: JsonObject?) = buildJsonObject {
            putJsonObject("200") { putJsonObject("content") { putJsonObject(ct) { schema?.let { put("schema", it) } } } }
        }
        fun string(format: String) = buildJsonObject { put("type", "string"); put("format", format) }
        val routes = mapOf(
            "downloadReport" to response("application/json;charset=UTF-8", string("byte")),
            "getBundle" to response("application/octet-stream", string("binary")),
            "getRefFile" to response("application/json", buildJsonObject { put("\$ref", "#/components/schemas/File") }),
            "getExpiry" to response("application/json;charset=UTF-8", string("date-time")),
            "getText" to response("text/plain", string("binary")),
            "getThing" to response("application/json", buildJsonObject { put("\$ref", "#/components/schemas/Thing") }),
            "getXml" to response("application/xml", buildJsonObject { put("\$ref", "#/components/schemas/Thing") }),
            "getZip" to response("application/zip", null),
            "getLoop" to response("application/json", buildJsonObject { put("\$ref", "#/components/schemas/LoopA") }),
        )
        val paths = buildJsonObject {
            for ((opId, responses) in routes) {
                putJsonObject("/api/3/$opId") { putJsonObject("get") { put("operationId", opId); put("responses", responses) } }
            }
        }
        val schemas = buildJsonObject {
            putJsonObject("File") { put("\$ref", "#/components/schemas/Bytes") }
            put("Bytes", string("binary"))
            putJsonObject("Thing") { put("type", "object") }
            putJsonObject("LoopA") { put("\$ref", "#/components/schemas/LoopB") }
            putJsonObject("LoopB") { put("\$ref", "#/components/schemas/LoopA") }
        }
        val responses = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(paths, schemas), "s", "f").ops.associate { it.opId to it.responses }

        // A file keeps its declared label verbatim; the runtime accepts anything for it.
        assertEquals(CatalogResponses("application/json;charset=UTF-8", binary = true), responses["downloadReport"])
        assertEquals(CatalogResponses("application/octet-stream", binary = true), responses["getBundle"])
        assertEquals(CatalogResponses("application/json", binary = true), responses["getRefFile"], "a \$ref chain is followed")
        assertEquals(CatalogResponses("text/plain", binary = true), responses["getText"])
        // A formatted string that is not a file is still JSON text.
        assertEquals(CatalogResponses("application/json", binary = false), responses["getExpiry"])
        assertEquals(CatalogResponses("application/json", binary = false), responses["getThing"])
        // Without a file schema the label decides, by the same test the runtime client applies.
        assertEquals(CatalogResponses("application/xml", binary = false), responses["getXml"])
        assertEquals(CatalogResponses("application/zip", binary = true), responses["getZip"])
        // A cycle of bare $refs describes no schema, so it cannot make a body a file.
        assertEquals(CatalogResponses("application/json", binary = false), responses["getLoop"])

        // A label nothing can parse fails generation rather than guessing text or file.
        val malformed = buildJsonObject {
            putJsonObject("/api/3/x") { putJsonObject("get") { put("operationId", "getX"); put("responses", response("zip", null)) } }
        }
        val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(malformed), "s", "f") }
        assertContains(e.message!!, "malformed response content type in \"getX\"")
    }

    @Test
    fun `build rules - only additive operations escape destructiveHint, and five POST searches are reads`() {
        fun catalog(family: ApiFamily, vararg routes: Triple<String, String, String>) = CatalogGenerator.buildCatalog(
            family,
            spec(buildJsonObject {
                for ((path, ops) in routes.groupBy { it.second }) {
                    putJsonObject(path) { for ((method, _, opId) in ops) putJsonObject(method) { put("operationId", opId) } }
                }
            }),
            "s",
            "f",
        ).ops.associateBy { it.opId }

        val console = catalog(
            ApiFamily.CONSOLE,
            Triple("post", "/api/3/things", "createThing"),
            Triple("put", "/api/3/things/tags", "addThingTag"),
            Triple("put", "/api/3/things/tagged", "tagThing"),
            Triple("post", "/api/3/things/scans", "startThingScan"),
            Triple("post", "/api/3/things/report", "generateThingReport"),
            Triple("post", "/api/3/things/connect", "reconnectThing"),
            // Replacing a whole list with [] deletes every entry, exactly as a DELETE would.
            Triple("put", "/api/3/things/all", "setThings"),
            Triple("put", "/api/3/things/one", "updateThing"),
            Triple("post", "/api/3/things/status", "setThingStatus"),
            Triple("put", "/api/3/things/password", "resetPassword"),
            Triple("post", "/api/3/things/2fa", "regenerateTwoFactorAuthentication"),
            Triple("post", "/api/3/things/stop", "stopThing"),
            // A DELETE is never additive, whatever its id says; 'add' must start a word.
            Triple("delete", "/api/3/things/cleanup", "startCleanup"),
            Triple("post", "/api/3/things/adder", "addendum"),
            // The admin operation is destructive even under an additive-looking id.
            Triple("post", "/api/3/administration/commands", "createCommand"),
            Triple("post", "/api/3/assets/search", "findAssets"),
            Triple("post", "/api/3/sonar_queries/search", "sonarQuerySearch"),
            // Only the listed routes are reads: another POST search, or the same path under PUT, is a write.
            Triple("post", "/api/3/sites/search", "findSites"),
            Triple("put", "/api/3/assets/search", "putSearch"),
            Triple("get", "/api/3/things", "getThings"),
        )
        val cloud = catalog(
            ApiFamily.CLOUD,
            Triple("post", "/v4/integration/assets", "searchIntegrationAssets"),
            Triple("post", "/v4/integration/sites", "getSites"),
            Triple("post", "/v4/integration/vulnerabilities", "searchIntegrationVulnerabilities"),
            Triple("post", "/v4/integration/scan", "startScan"),
            Triple("post", "/v4/integration/scan/stop", "stopScan"),
        )
        val all = console + cloud
        fun flags(opId: String) = all.getValue(opId).let { "readOnly=${it.readOnly} destructive=${it.destructive}" }

        val additive = listOf("createThing", "addThingTag", "tagThing", "startThingScan", "generateThingReport", "reconnectThing", "startScan")
        val destructive = listOf(
            "setThings", "updateThing", "setThingStatus", "resetPassword", "regenerateTwoFactorAuthentication", "stopThing",
            "startCleanup", "addendum", "createCommand", "findSites", "putSearch", "stopScan",
        )
        val reads = listOf("findAssets", "sonarQuerySearch", "getThings", "searchIntegrationAssets", "getSites", "searchIntegrationVulnerabilities")
        assertEquals(all.keys, (additive + destructive + reads).toSet())
        for (id in additive) assertEquals("readOnly=false destructive=false", flags(id), id)
        for (id in destructive) assertEquals("readOnly=false destructive=true", flags(id), id)
        for (id in reads) assertEquals("readOnly=true destructive=false", flags(id), id)
        assertTrue(all.getValue("createCommand").admin)
    }

    /** One minimal operation; [withId] declares the `{id}` path parameter its route needs. */
    private fun operation(opId: String, withId: Boolean = false) = buildJsonObject {
        put("operationId", opId)
        if (withId) {
            putJsonArray("parameters") {
                add(buildJsonObject { put("name", "id"); put("in", "path"); put("required", true); putJsonObject("schema") { put("type", "integer") } })
            }
        }
    }

    /** Every route of `CatalogLoader.SENSITIVE_OPS`, plus the shared secret's revoke, as a spec's paths. */
    private val secretPaths = buildJsonObject {
        putJsonObject("/api/3/users/{id}/2FA") {
            put("get", operation("getTwoFactorAuthenticationKey", withId = true))
            put("post", operation("regenerateTwoFactorAuthentication", withId = true))
            put("put", operation("setTwoFactorAuthentication", withId = true))
        }
        putJsonObject("/api/3/users/{id}/password") { put("put", operation("resetPassword", withId = true)) }
        putJsonObject("/api/3/scan_engines/shared_secret") {
            put("get", operation("getCurrentSharedSecret"))
            put("post", operation("createSharedSecret"))
            put("delete", operation("deleteSharedSecret"))
        }
    }

    @Test
    fun `build rules - the routes that return or set an authentication secret are sensitive`() {
        val paths = JsonObject(
            secretPaths + buildJsonObject {
                putJsonObject("/api/3/scan_engines/shared_secret/time_to_live") { put("get", operation("getCurrentSharedSecretTimeToLive")) }
                putJsonObject("/api/3/users/{id}") { put("get", operation("getUser", withId = true)); put("put", operation("updateUser", withId = true)) }
            },
        )
        val ops = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(paths), "s", "f").ops.associateBy { it.opId }
        val sensitive = ops.values.filter { it.sensitive }
        assertEquals(CatalogLoader.SENSITIVE_OPS, sensitive.map { it.method to it.path }.toSet())
        assertEquals(
            setOf(
                "get_two_factor_authentication_key", "regenerate_two_factor_authentication", "set_two_factor_authentication",
                "reset_password", "get_current_shared_secret", "create_shared_secret",
            ),
            sensitive.map { it.name }.toSet(),
        )
        // The flag is independent of the others: the seed read is still a read, the reset still destructive.
        assertTrue(ops.getValue("getTwoFactorAuthenticationKey").readOnly)
        assertTrue(ops.getValue("resetPassword").destructive)
        // Revoking the secret returns nothing, and a neighbouring route is ordinary.
        for (id in listOf("deleteSharedSecret", "getCurrentSharedSecretTimeToLive", "getUser", "updateUser")) {
            assertFalse(ops.getValue(id).sensitive, id)
        }
    }

    @Test
    fun `build rules - errors`() {
        fun fails(paths: JsonObject, schemas: JsonObject = JsonObject(emptyMap())) =
            assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(paths, schemas), "s", "f") }

        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonArray("parameters") { } } }).message!!.contains("path-level"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { } } }).message!!.contains("operationId"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { put("operationId", "a"); putJsonArray("parameters") { add(buildJsonObject { put("\$ref", "#/p" ) }) } } } }).message!!.contains("\$ref"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { put("operationId", "a"); putJsonArray("parameters") { add(buildJsonObject { put("name", "body"); put("in", "query") }) } } } }).message!!.contains("body"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { put("operationId", "a"); putJsonArray("parameters") { add(buildJsonObject { put("name", "q"); put("in", "query") }); add(buildJsonObject { put("name", "q"); put("in", "query") }) } } } }).message!!.contains("duplicate"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("post") { put("operationId", "a"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/xml") { } } } } } }).message!!.contains("content types"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("post") { put("operationId", "a"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/Nope") } } } } } } }).message!!.contains("unknown schema"))
        assertTrue(fails(buildJsonObject { putJsonObject("/x") { putJsonObject("post") { put("operationId", "a"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/defs/X") } } } } } } }).message!!.contains("unsupported"))

        // A file upload declared as a JSON property can never be sent as JSON; a new one must be noticed.
        fun jsonBody(schema: String) = buildJsonObject {
            putJsonObject("/api/3/upload") { putJsonObject("post") { put("operationId", "upload"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/$schema") } } } } } }
        }
        val binary = buildJsonObject {
            putJsonObject("Upload") { putJsonObject("properties") { putJsonObject("file") { putJsonObject("items") { put("type", "string"); put("format", "binary") } } } }
        }
        assertTrue(fails(jsonBody("Upload"), binary).message!!.contains("binary"))

        // Discriminators this generator cannot flatten fail closed instead of silently hiding fields.
        val nested = buildJsonObject {
            putJsonObject("Base") { putJsonObject("discriminator") { put("propertyName", "kind"); putJsonObject("mapping") { put("x", "#/components/schemas/Sub") } } }
            putJsonObject("Sub") { putJsonObject("discriminator") { put("propertyName", "kind"); putJsonObject("mapping") { put("y", "#/components/schemas/Base") } } }
        }
        assertTrue(fails(jsonBody("Base"), nested).message!!.contains("discriminator"))
        val unmapped = buildJsonObject { putJsonObject("Base") { putJsonObject("discriminator") { put("propertyName", "kind") } } }
        assertTrue(fails(jsonBody("Base"), unmapped).message!!.contains("discriminator"))
        val unnamed = buildJsonObject { putJsonObject("Base") { putJsonObject("discriminator") { putJsonObject("mapping") { put("x", "#/components/schemas/Base") } } } }
        assertTrue(fails(jsonBody("Base"), unnamed).message!!.contains("discriminator"))
    }

    @Test
    fun `build rules - nested schemas are typed and scalar parameters keep no object shape`() {
        val schemas = buildJsonObject {
            putJsonObject("Key") {
                put("description", "\${key.description}, \${key.alt.description}")
                putJsonObject("properties") { putJsonObject("id") { put("description", "\${key.id.description}") } }
                putJsonArray("required") { add(JsonPrimitive("id")) }
            }
            putJsonObject("Form") {
                put("description", "\${form.description}")
                putJsonObject("properties") {
                    putJsonObject("ids") { put("description", "The ids."); putJsonObject("items") { put("format", "int64"); put("description", "The ids.") } }
                    putJsonObject("names") { put("type", "array"); put("description", "Names."); putJsonObject("items") { put("type", "string"); put("description", "One name.") } }
                    putJsonObject("inner") {
                        putJsonObject("properties") {
                            putJsonObject("n") { put("format", "int32") }
                            putJsonObject("x") { put("format", "double") }
                            putJsonObject("at") { put("format", "date-time") }
                            putJsonObject("kind") { putJsonArray("enum") { add(JsonPrimitive("a")) } }
                            putJsonObject("code") { putJsonArray("enum") { add(JsonPrimitive(1)) } }
                            putJsonObject("bag") { put("additionalProperties", true) }
                            putJsonObject("free") { put("description", "Anything.") }
                            putJsonObject("odd") { put("type", "string"); put("format", "<property>[,ASC|DESC]") }
                        }
                    }
                    putJsonObject("choice") { putJsonArray("oneOf") { add(buildJsonObject { put("type", "string") }) } }
                    putJsonObject("range") { put("\$ref", "#/components/schemas/RangeResource") }
                    putJsonObject("trend") { put("\$ref", "#/components/schemas/RiskTrendResource") }
                }
            }
            for (name in listOf("RangeResource", "RiskTrendResource")) {
                putJsonObject(name) {
                    putJsonObject("properties") {
                        putJsonObject("from") { put("type", "object"); putJsonArray("enum") { add(JsonPrimitive("P1Y")); add(JsonPrimitive("<date>")) } }
                    }
                }
            }
        }
        val paths = buildJsonObject {
            putJsonObject("/v4/things/{id}") {
                putJsonObject("post") {
                    put("operationId", "makeThing")
                    putJsonArray("parameters") {
                        add(buildJsonObject { put("name", "id"); put("in", "path"); put("description", "The thing."); putJsonObject("schema") { put("\$ref", "#/components/schemas/Key") } })
                        add(buildJsonObject { put("name", "sort"); put("in", "query"); putJsonObject("schema") { put("type", "string"); put("format", "<property>[,ASC|DESC]"); put("example", "id,ASC") } })
                    }
                    putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/Form") } } } }
                }
            }
        }
        val op = CatalogGenerator.buildCatalog(ApiFamily.CLOUD, spec(paths, schemas), "s", "f").ops.single()

        // An object-shaped schema behind a path parameter is still one string on the wire.
        assertEquals(buildJsonObject { put("type", "string"); put("description", "The thing.") }, op.params.single { it.name == "id" }.schema)
        // v4 sort is declared a string, but its own text says it repeats, as v3's array does.
        val sort = op.params.single { it.name == "sort" }
        assertTrue(sort.array)
        assertEquals(buildJsonObject { put("type", "array"); putJsonObject("items") { put("type", "string") } }, sort.schema)

        val body = op.body!!.schema
        assertNull(body["description"], "an unrendered placeholder is not a description")
        val props = body["properties"]!!.jsonObject
        assertEquals(buildJsonObject { put("description", "The ids."); putJsonObject("items") { put("format", "int64"); put("type", "integer") }; put("type", "array") }, props["ids"])
        assertEquals("One name.", props["names"]!!.jsonObject["items"]!!.jsonObject.str("description"), "a different item description is kept")
        val inner = props["inner"]!!.jsonObject
        assertEquals("object", inner.str("type"))
        val types = inner["properties"]!!.jsonObject.mapValues { (_, s) -> s.jsonObject.str("type") }
        assertEquals(mapOf("n" to "integer", "x" to "number", "at" to "string", "kind" to "string", "code" to null, "bag" to "object", "free" to null, "odd" to "string"), types)
        assertNull(inner["properties"]!!.jsonObject["odd"]!!.jsonObject["format"], "a format that is prose is dropped")
        assertNull(props["choice"]!!.jsonObject["type"], "a composition is left untyped")
        for (trend in listOf("range", "trend")) {
            val from = props[trend]!!.jsonObject["properties"]!!.jsonObject["from"]!!.jsonObject
            assertEquals("string", from.str("type"), trend)
            assertNull(from["enum"], "$trend.from keeps an enum no value can satisfy")
            assertContains(from.str("description")!!, "ISO-8601")
        }
    }

    @Test
    fun `build rules - the depth guard counts nested refs, not JSON nesting`() {
        val schemas = buildJsonObject {
            for (i in 0..8) putJsonObject("S$i") { putJsonObject("properties") { putJsonObject("next") { put("\$ref", "#/components/schemas/S${i + 1}") } } }
            putJsonObject("S9") { put("type", "string") }
            // Ten levels of inline nesting, one ref at the bottom.
            var deep: JsonObject = buildJsonObject { put("\$ref", "#/components/schemas/Leaf") }
            repeat(5) { deep = buildJsonObject { put("type", "array"); put("items", buildJsonObject { putJsonObject("properties") { put("x", deep) } }) } }
            put("Deep", buildJsonObject { putJsonObject("properties") { put("x", deep) } })
            putJsonObject("Leaf") { put("type", "string"); put("description", "The leaf.") }
        }
        fun body(schema: String) = buildJsonObject {
            putJsonObject("/$schema") { putJsonObject("put") { put("operationId", "put$schema"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/$schema") } } } } } }
        }
        val chain = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(body("S0"), schemas), "s", "f").ops.single().body!!.schema
        var node: JsonObject = chain
        repeat(CatalogGenerator.MAX_DEPTH) { node = assertNotNull(node["properties"], "cut before ${CatalogGenerator.MAX_DEPTH} refs").jsonObject["next"]!!.jsonObject }
        assertEquals("S${CatalogGenerator.MAX_DEPTH} (nested object; see the Rapid7 API documentation)", node.str("description"))

        var deep: JsonObject = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(body("Deep"), schemas), "s", "f").ops.single().body!!.schema
        repeat(5) { deep = deep["properties"]!!.jsonObject["x"]!!.jsonObject["items"]!!.jsonObject }
        assertEquals("The leaf.", deep["properties"]!!.jsonObject["x"]!!.jsonObject.str("description"))
    }

    @Test
    fun `build rules - a discriminator mapping merges its subtypes' fields into the base`() {
        val long = "L".repeat(300)
        val schemas = buildJsonObject {
            putJsonObject("Account") {
                put("description", "Pick a service.")
                putJsonObject("discriminator") { put("propertyName", "service"); putJsonObject("mapping") { put("a", "#/components/schemas/A"); put("b", "#/components/schemas/B") } }
                putJsonObject("properties") { putJsonObject("service") { put("type", "string"); putJsonArray("enum") { add(JsonPrimitive("a")); add(JsonPrimitive("b")) } } }
            }
            putJsonObject("A") {
                putJsonArray("required") { add(JsonPrimitive("user")) }
                putJsonObject("properties") {
                    putJsonObject("service") { put("type", "string"); put("description", "Overridden by the base.") }
                    putJsonObject("user") { put("type", "string"); put("description", "The user.") }
                    putJsonObject("level") { put("type", "string"); put("description", long); putJsonArray("enum") { add(JsonPrimitive("none")) } }
                }
            }
            putJsonObject("B") {
                putJsonObject("properties") {
                    putJsonObject("user") { put("type", "integer"); put("description", "Loses to the first definition.") }
                    putJsonObject("key") { put("type", "string") }
                }
            }
            putJsonObject("C") { putJsonObject("properties") { putJsonObject("service") { put("type", "string") } } }
            putJsonObject("Wrapper") {
                putJsonObject("properties") { putJsonObject("account") { put("\$ref", "#/components/schemas/Account") } }
            }
            // A discriminator beside oneOf is already expressed by the oneOf; it is only stripped.
            putJsonObject("Either") {
                putJsonObject("discriminator") { put("propertyName", "service"); putJsonObject("mapping") { put("a", "#/components/schemas/A") } }
                putJsonArray("oneOf") { add(buildJsonObject { put("\$ref", "#/components/schemas/B") }) }
            }
            putJsonObject("Bare") {
                putJsonObject("discriminator") { put("propertyName", "service"); putJsonObject("mapping") { put("c", "#/components/schemas/C") } }
            }
        }
        fun body(schema: String) = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(buildJsonObject {
            putJsonObject("/$schema") { putJsonObject("put") { put("operationId", "put$schema"); putJsonObject("requestBody") { putJsonObject("content") { putJsonObject("application/json") { putJsonObject("schema") { put("\$ref", "#/components/schemas/$schema") } } } } } }
        }, schemas), "s", "f").ops.single().body!!.schema

        val account = body("Wrapper")["properties"]!!.jsonObject["account"]!!.jsonObject
        assertEquals("object", account.str("type"))
        assertNull(account["required"], "a subtype's required list is not the base's")
        assertEquals("Pick a service. Fields by service: a: user, level; b: user, key.", account.str("description"))
        val props = account["properties"]!!.jsonObject
        assertEquals(listOf("service", "user", "level", "key"), props.keys.toList())
        assertEquals(buildJsonObject { put("type", "string"); putJsonArray("enum") { add(JsonPrimitive("a")); add(JsonPrimitive("b")) } }, props["service"], "the base's own property wins")
        assertEquals("string", props["user"]!!.jsonObject.str("type"), "the first definition wins")
        assertEquals("The user. (service: a, b)", props["user"]!!.jsonObject.str("description"))
        val level = props["level"]!!.jsonObject
        assertEquals(listOf("none"), level["enum"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("L".repeat(199) + "… (service: a)", level.str("description"))
        assertEquals("(service: b)", props["key"]!!.jsonObject.str("description"))

        val either = body("Either")
        assertNull(either["discriminator"])
        assertNull(either["properties"])
        // The selector itself is not listed as a field, but a base that lacks it still gets it.
        val bare = body("Bare")
        assertEquals("Fields by service: c: none.", bare.str("description"))
        assertEquals(listOf("service"), bare["properties"]!!.jsonObject.keys.toList())
    }

    @Test
    fun `build rules - activate_license drops the JSON body its own text says is multipart`() {
        val paths = buildJsonObject {
            putJsonObject("/api/3/administration/license") {
                putJsonObject("post") {
                    put("operationId", "activateLicense")
                    putJsonArray("parameters") { add(buildJsonObject { put("name", "key"); put("in", "query"); putJsonObject("schema") { put("type", "string") } }) }
                    putJsonObject("requestBody") {
                        putJsonObject("content") {
                            putJsonObject("application/json") {
                                putJsonObject("schema") { put("type", "object"); putJsonObject("properties") { putJsonObject("license") { put("type", "string"); put("format", "binary") } } }
                            }
                        }
                    }
                }
            }
        }
        val op = CatalogGenerator.buildCatalog(ApiFamily.CONSOLE, spec(paths), "s", "f").ops.single()
        assertNull(op.body)
        assertEquals(listOf("key"), op.params.map { it.name })
    }

    @Test
    fun `cloud family drops the region parameter and prefixes names`() {
        val paths = buildJsonObject {
            putJsonObject("/v4/integration/scan") {
                putJsonObject("get") {
                    put("operationId", "getScans")
                    putJsonArray("parameters") {
                        add(buildJsonObject { put("name", "region"); put("in", "path"); put("required", true) })
                        add(buildJsonObject { put("name", "page"); put("in", "query"); put("schema", buildJsonObject { put("type", "integer") }) })
                    }
                }
            }
        }
        val cat = CatalogGenerator.buildCatalog(ApiFamily.CLOUD, spec(paths), "s", "f")
        val op = cat.ops.single()
        assertEquals("cloud_get_scans", op.name)
        assertEquals(listOf("page"), op.params.map { it.name })
        assertEquals("Untagged", op.tag)
        assertEquals("none", op.responses.success)
    }

    @Test
    fun `generate rejects cross-family duplicate names`() {
        val dir = createTempDirectory("dup-specs")
        try {
            val same = Json.encodeToString(JsonObject.serializer(), spec(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { put("operationId", "getX") } } }))
            for (src in CatalogGenerator.SOURCES) Files.writeString(dir.resolve(src.specFile), same)
            // v4 names are prefixed, so no collision here; force one by naming the cloud op "cloud_get_x" in v3.
            Files.writeString(dir.resolve("insightvm-console-v3.json"), Json.encodeToString(JsonObject.serializer(), spec(buildJsonObject { putJsonObject("/x") { putJsonObject("get") { put("operationId", "cloudGetX") } } })))
            val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.generate(dir) }
            assertContains(e.message!!, "duplicate tool name cloud_get_x")
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `generate writes the console's search-criteria reference and requires one`() {
        val dir = createTempDirectory("criteria-specs")
        try {
            fun write(console: JsonObject) {
                Files.writeString(dir.resolve("insightvm-console-v3.json"), Json.encodeToString(JsonObject.serializer(), console))
                Files.writeString(dir.resolve("insightvm-cloud-v4.json"), Json.encodeToString(JsonObject.serializer(), spec(buildJsonObject { putJsonObject("/y") { putJsonObject("get") { put("operationId", "getY") } } })))
            }
            write(spec(criteriaPaths, criteriaSchemas()))
            val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.generate(dir) }
            assertContains(e.message!!, "specs/insightvm-console-v3.json has no search-criteria reference")

            write(spec(JsonObject(criteriaPaths + secretPaths), criteriaSchemas(), criteriaIntro))
            val generated = CatalogGenerator.generate(dir)
            assertEquals(CatalogGenerator.OUTPUTS, generated.keys.toList())
            val reference = SearchCriteria.parse(generated.getValue(CatalogGenerator.SEARCH_CRITERIA_FILE))
            assertEquals(listOf("risk-score", "host-type"), reference.asset.map { it.name })
            assertEquals("specs/insightvm-console-v3.json", reference.meta.generatedFrom)
            assertEquals(64, reference.meta.specSha256.length)
            // The catalog was built against the same reference: its filter lists the same fields.
            val find = CatalogLoader.parse(generated.getValue("v3.json"), ApiFamily.CONSOLE).ops.single { it.opId == "findAssets" }
            assertEquals(2, find.body!!.schema.at("properties", "filters", "items", "properties", "field")["enum"]!!.jsonArray.size)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    /**
     * The secret gate is keyed by route, so a route the specification renames would otherwise be
     * published as an ordinary tool: generation stops instead.
     */
    @Test
    fun `generate fails when the specification lacks a route the secret gate names`() {
        val dir = createTempDirectory("secret-specs")
        try {
            val cloud = spec(buildJsonObject { putJsonObject("/y") { putJsonObject("get") { put("operationId", "getY") } } })
            Files.writeString(dir.resolve("insightvm-cloud-v4.json"), Json.encodeToString(JsonObject.serializer(), cloud))
            val renamed = JsonObject(
                secretPaths - "/api/3/users/{id}/password" + buildJsonObject {
                    putJsonObject("/api/3/users/{id}/credentials") { put("put", operation("resetPassword", withId = true)) }
                },
            )
            val console = spec(JsonObject(criteriaPaths + renamed), criteriaSchemas(), criteriaIntro)
            Files.writeString(dir.resolve("insightvm-console-v3.json"), Json.encodeToString(JsonObject.serializer(), console))
            val e = assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.generate(dir) }
            assertContains(e.message!!, "PUT /api/3/users/{id}/password")
            assertContains(e.message!!, "SENSITIVE_OPS")
            assertFalse(e.message!!.contains("2FA"), "only the missing route is named: ${e.message}")
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    // ---------------------------------------------------------------- the committed catalog

    // These read the bundled catalog, so they run without specs/; the drift test above ties it to a fresh run.

    private val v3: Catalog by lazy { CatalogLoader.load(ApiFamily.CONSOLE) }
    private val v4: Catalog by lazy { CatalogLoader.load(ApiFamily.CLOUD) }

    private fun Catalog.op(name: String): CatalogOp = ops.single { it.name == name }

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    /** Follow [keys] down from a schema node, failing with the first key that is missing. */
    private fun JsonObject.at(vararg keys: String): JsonObject =
        keys.fold(this) { node, key -> assertNotNull(node[key], "missing '$key'").jsonObject }

    /** Every JSON object in the committed [file], depth first. */
    private fun objects(file: String): Sequence<JsonObject> = sequence {
        val stack = ArrayDeque<JsonElement>(listOf(Json.parseToJsonElement(Files.readString(committed.resolve(file)))))
        while (stack.isNotEmpty()) {
            when (val e = stack.removeLast()) {
                is JsonObject -> { yield(e); e.values.forEach { stack.addLast(it) } }
                is JsonArray -> e.forEach { stack.addLast(it) }
                else -> Unit
            }
        }
    }

    @Test
    fun `catalog - v4 query-language examples and sort placeholders survive text cleaning`() {
        val asset = v4.op("cloud_search_integration_assets").body!!.schema.at("properties", "asset")
        assertContains(asset.str("description")!!, "last_scan_end >= '2025-09-13T00:02:01Z' && cvss_score >= 9")
        for (name in listOf("cloud_search_integration_assets", "cloud_get_sites", "cloud_search_integration_vulnerabilities")) {
            val sort = v4.op(name).params.single { it.name == "sort" }
            assertContains(sort.schema.str("description")!!, "in the format: `‹property›[,ASC|DESC]`", message = name)
        }
        for (file in listOf("v3.json", "v4.json")) {
            val formats = objects(file).mapNotNull { it.str("format") }.toSortedSet()
            assertTrue(formats.none { '<' in it || '‹' in it }, "$file formats: $formats")
        }
    }

    @Test
    fun `catalog - nested schemas are typed and parameters are clean`() {
        val scan = v4.op("cloud_start_scan").body!!.schema
        for (field in listOf("asset_ids", "credential_sources", "engine_ids", "solution_ids", "vulnerability_ids")) {
            assertEquals("array", scan.at("properties", field).str("type"), field)
        }
        assertEquals("array", v4.op("cloud_update_scan_engine_configuration").body!!.schema.at("properties", "properties").str("type"))
        assertEquals("object", v3.op("create_asset_group").body!!.schema.at("properties", "searchCriteria").str("type"))

        val roleId = v3.op("get_role").params.single { it.name == "id" }.schema
        assertEquals(buildJsonObject { put("type", "string"); put("description", "The identifier of the role.") }, roleId)
        val shaped = (v3.ops + v4.ops).flatMap { op -> op.params.filter { "properties" in it.schema || "required" in it.schema }.map { "${op.name}.${it.name}" } }
        assertEquals(emptyList(), shaped, "scalar parameters carrying an object's properties")

        for (op in listOf("cloud_search_integration_assets", "cloud_get_sites", "cloud_search_integration_vulnerabilities")) {
            val sort = v4.op(op).params.single { it.name == "sort" }
            assertTrue(sort.array, op)
            assertEquals("string", sort.schema.at("items").str("type"), op)
        }
    }

    @Test
    fun `catalog - spec defects are corrected rather than passed through`() {
        for (file in listOf("v3.json", "v4.json")) {
            assertFalse(Files.readString(committed.resolve(file)).contains("\${"), "$file carries an unrendered template key")
        }
        for (op in listOf("create_report", "update_report")) {
            for (trend in listOf("range", "riskTrend")) {
                val from = v3.op(op).body!!.schema.at("properties", trend, "properties", "from")
                assertEquals("string", from.str("type"), "$op.$trend.from")
                assertNull(from["enum"], "$op.$trend.from keeps an enum no value can satisfy")
            }
        }
        val page = v3.op("create_asset").body!!.schema
            .at("properties", "services", "items", "properties", "webApplications", "items", "properties", "pages", "items")
        assertEquals(15, page.at("properties", "linkType")["enum"]!!.jsonArray.size)

        val cuts = listOf("v3.json", "v4.json").flatMap { file ->
            objects(file).mapNotNull { it.str("description") }.filter { it.endsWith("(nested object; see the Rapid7 API documentation)") }.map { it.substringBefore(' ') }.toList()
        }.toSet()
        assertEquals(setOf("UserEdit", "ScanForm"), cuts, "only genuine cycles are cut")

        val duplicated = listOf("v3.json", "v4.json").sumOf { file ->
            objects(file).count { node ->
                val items = node["items"] as? JsonObject
                items != null && node.str("description") != null && items.str("description") == node.str("description")
            }
        }
        assertEquals(0, duplicated, "array item descriptions that repeat their parent's")
    }

    @Test
    fun `catalog - every write that is not purely additive is destructive`() {
        val all = (v3.ops + v4.ops).associateBy { it.name }
        val writes = all.values.filter { !it.readOnly }
        assertEquals(114, writes.count { it.destructive })
        assertEquals(38, writes.count { !it.destructive })
        assertTrue(all.values.none { it.readOnly && it.destructive })
        // Each of these can remove or overwrite state: a list replaced with [], a scan stopped, a
        // credential reset, an arbitrary console command.
        for (name in listOf(
            "set_site_scan_schedules", "set_site_users", "update_included_targets", "set_scan_status", "reset_password",
            "regenerate_two_factor_authentication", "execute_command", "enable_site_credential", "activate_license",
            "cloud_update_scan_engine_configuration", "cloud_stop_scan", "delete_site",
        )) {
            assertTrue(all.getValue(name).destructive, name)
        }
        for (name in listOf("create_site", "add_site_tag", "tag_asset", "start_scan", "generate_report", "cloud_start_scan")) {
            assertFalse(all.getValue(name).destructive, name)
        }
    }

    @Test
    fun `catalog - the five POST searches are the only non-GET reads`() {
        val reads = (v3.ops + v4.ops).filter { it.readOnly && it.method != "GET" }
        assertEquals(
            listOf("cloud_get_sites", "cloud_search_integration_assets", "cloud_search_integration_vulnerabilities", "find_assets", "sonar_query_search"),
            reads.map { it.name }.sorted(),
        )
        assertTrue(reads.all { it.method == "POST" && !it.destructive && !it.admin })
    }

    /**
     * Regression: find_assets and the seven other search-criteria bodies offered `field` and
     * `operator` as free text, typed the values `object`, and pointed at "Search Criteria", which no
     * tool carries. v4's own search-criteria section never reached a tool either.
     */
    @Test
    fun `catalog - search-criteria filters carry the reference's fields and operators`() {
        fun filter(op: String, vararg path: String) = v3.op(op).body!!.schema.at(*path, "filters", "items")
        fun enumOf(filter: JsonObject, property: String) = filter.at("properties", property)["enum"]!!.jsonArray.map { it.jsonPrimitive.content }

        val find = filter("find_assets", "properties")
        val fields = enumOf(find, "field")
        assertEquals(47, fields.size)
        assertTrue("vulnerability-cvss-v3-score" in fields && "risk-score" in fields && "vAsset-cluster" in fields, fields.toString())
        val operators = enumOf(find, "operator")
        assertEquals(26, operators.size)
        assertTrue("is-greater-than" in operators && "in-range" in operators && "does-not-include" in operators, operators.toString())
        for (property in listOf("value", "lower", "upper")) {
            assertNull(find.at("properties", property)["type"], "$property is typed although an operator may take a string or a number")
        }
        assertEquals(JsonObject(emptyMap()), find.at("properties", "values", "items"))

        val assetBodies = mapOf(
            "create_asset_group" to listOf("properties", "searchCriteria", "properties"),
            "update_asset_group" to listOf("properties", "searchCriteria", "properties"),
            "set_asset_group_search_criteria" to listOf("properties"),
            "create_tag" to listOf("properties", "searchCriteria", "properties"),
            "update_tag" to listOf("properties", "searchCriteria", "properties"),
            "update_tag_search_criteria" to listOf("properties"),
        )
        for ((op, path) in assetBodies) assertEquals(find, filter(op, *path.toTypedArray()), op)

        val discovery = filter("set_site_discovery_search_criteria", "properties")
        val connectionTypes = v3.op("set_site_discovery_search_criteria").body!!.schema.at("properties", "connectionType")["enum"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertEquals(23, enumOf(discovery, "field").size)
        assertTrue("power-state" in enumOf(discovery, "field"))
        assertEquals(14, enumOf(discovery, "operator").size)
        val reference = SearchCriteria.load()
        assertEquals(connectionTypes.toSet(), reference.discovery.flatMap { it.connectionTypes }.toSet(), "every connectionType has a fields table")
        assertEquals(reference.asset.map { it.name }, fields)

        for (file in listOf("v3.json", "v4.json")) {
            val text = Files.readString(committed.resolve(file))
            assertFalse(text.contains("See Search Criteria") || text.contains("Search Criteria for more information"), "$file still points at the unreachable section")
        }
        assertEquals(
            "Updates the search criteria associated with the tag. ${CatalogGenerator.ASSET_CRITERIA_POINTER}",
            v3.op("update_tag_search_criteria").description,
        )
        assertContains(v3.op("find_assets").body!!.schema.at("properties", "filters").str("description")!!, CatalogGenerator.ASSET_CRITERIA_POINTER)
        assertContains(v3.op("create_asset_group").description, CatalogGenerator.ASSET_CRITERIA_POINTER)
        assertContains(v3.op("set_site_discovery_search_criteria").body!!.schema.at("properties", "filters").str("description")!!, CatalogGenerator.DISCOVERY_CRITERIA_POINTER)

        val note = v4.op("cloud_search_integration_assets").body!!.schema.str("description")!!
        assertContains(note, "A `vulnerability` chunk by itself does not change the number of assets returned")
        assertContains(note, "\"vulnerability\": \"cvss_score >= 9\"")
        assertFalse(note.endsWith("…"), "the note was cut")
        // Regression: the note describes an `asset` chunk and gave {"asset": ...} examples, and was also put
        // on the vulnerabilities search, whose VulnerabilitySearch body has no `asset` property. The model
        // then sent one, which the endpoint does not define.
        val vulnerabilities = v4.op("cloud_search_integration_vulnerabilities").body!!.schema
        assertEquals(setOf("vulnerability"), vulnerabilities.at("properties").keys)
        val vulnerabilitiesText = vulnerabilities.str("description")!!
        assertFalse(vulnerabilitiesText.contains("`asset`") || vulnerabilitiesText.contains("\"asset\""), vulnerabilitiesText)
        assertEquals(
            listOf("cloud_search_integration_assets"),
            v4.ops.filter { it.body?.schema?.str("description")?.contains("two independent chunks") == true }.map { it.name },
        )
    }

    @Test
    fun `catalog - the search-criteria reference holds every table of the introduction`() {
        val reference = SearchCriteria.load()
        assertEquals(47, reference.asset.size)
        assertEquals(20, reference.asset.count { it.values.isNotEmpty() })
        assertEquals(listOf("0=IPv4", "1=IPv6"), reference.asset.single { it.name == "alternate-address-type" }.values)
        assertEquals(listOf("L=Low", "M=Medium", "H=High"), reference.asset.single { it.name == "cvss-access-complexity" }.values)
        assertEquals(listOf("created", "running", "paused", "restarting", "exited", "dead", "unknown"), reference.asset.single { it.name == "container-status" }.values)
        // The table's stray spaces (` in-range`, ` is-not-applied`) are not part of the names.
        assertEquals(listOf("is", "is-not", "in-range"), reference.asset.single { it.name == "open-ports" }.operators)
        // 26 rows, one of them (not-contains) an alias of a name the table also lists.
        assertEquals(25, reference.operators.size)
        assertEquals(mapOf("lower" to "numeric", "upper" to "numeric"), reference.operators["in-range"])
        assertEquals(mapOf("value" to "numeric (days)"), reference.operators["is-within-the-last"])
        // The spec's Operator Properties table lists these arrays under `value`, but its filter schema says
        // `value` is "the single value" and has a separate array property, `values`. The schema wins.
        for (listOperator in listOf("in", "not-in", "includes")) {
            assertEquals(mapOf("values" to "Array[string]"), reference.operators[listOperator], listOperator)
        }
        assertTrue(reference.operators.values.none { reads -> reads["value"]?.startsWith("Array") == true }, "no array is left under `value`")
        assertEquals(emptyMap(), reference.operators["is-applied"])
        for ((alias, name) in SearchCriteriaTables.OPERATOR_ALIASES) {
            assertNotNull(reference.operators[name], "$alias → $name")
            assertNull(reference.operators[alias])
        }
        assertNull(reference.operators["does-not-include"], "the spec documents no properties for it")
        assertEquals(listOf("ActiveSync", "AWS", "DHCP", "Sonar", "vSphere"), reference.discovery.map { it.name })
        assertEquals(listOf("activesync-ldap", "activesync-office365", "activesync-powershell"), reference.discovery.first().connectionTypes)
        val vsphere = reference.discovery.single { it.name == "vSphere" }
        assertEquals(listOf("poweredOn", "poweredOff", "suspended"), vsphere.fields.single { it.name == "power-state" }.values)
        assertEquals(CatalogLoader.load(ApiFamily.CONSOLE).meta.specSha256, reference.meta.specSha256)
    }

    @Test
    fun `catalog - activate_license offers only the activation key`() {
        val op = v3.op("activate_license")
        assertNull(op.body, "the spec says the license file must be multipart/form-data, which this server cannot send")
        assertEquals(listOf("key"), op.params.map { it.name })
    }

    @Test
    fun `catalog - credential bodies expose every service-specific field`() {
        val accounts = mapOf(
            "create_shared_credential" to v3.op("create_shared_credential").body!!.schema.at("properties", "account"),
            "update_shared_credential" to v3.op("update_shared_credential").body!!.schema.at("properties", "account"),
            "create_site_credential" to v3.op("create_site_credential").body!!.schema.at("properties", "account"),
            "update_site_credential" to v3.op("update_site_credential").body!!.schema.at("properties", "account"),
            "set_site_credentials" to v3.op("set_site_credentials").body!!.schema.at("items", "properties", "account"),
        )
        for ((op, account) in accounts) {
            val props = account.at("properties")
            assertEquals(25, props.size, op)
            for (field in listOf("username", "password", "pemKey", "privateKeyPassword", "communityName", "permissionElevation", "authenticationType")) {
                assertTrue(field in props, "$op lacks $field")
            }
            assertEquals(
                listOf("none", "sudo", "sudosu", "su", "pbrun", "privileged-exec"),
                props.at("permissionElevation")["enum"]!!.jsonArray.map { it.jsonPrimitive.content },
            )
            assertEquals(25, props.at("service")["enum"]!!.jsonArray.size, "$op service enum")
            assertNull(account["required"], "$op account gained a subtype's required list")
            assertContains(props.at("pemKey").str("description")!!, "(service: ssh-key)")
            assertContains(account.str("description")!!, "Fields by service: as400: ")
            assertContains(account.str("description")!!, "snmp: communityName;")
        }
    }
}
