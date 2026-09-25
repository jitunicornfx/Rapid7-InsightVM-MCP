package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogGenerator
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
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
    }

    @Test
    fun `write and drift round-trip through a directory`() {
        requireSpecs()
        val dir = createTempDirectory("catalog-out")
        try {
            assertEquals(listOf("v3.json", "v4.json"), CatalogGenerator.drift(specs, dir))
            val written = CatalogGenerator.write(specs, dir)
            assertEquals(2, written.size)
            assertTrue(written.all { Files.size(it) > 1000 })
            assertEquals(emptyList(), CatalogGenerator.drift(specs, dir))
            Files.writeString(dir.resolve("v4.json"), "{}")
            assertEquals(listOf("v4.json"), CatalogGenerator.drift(specs, dir))
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

    @Test
    fun `snake case`() {
        assertEquals("get_site_scan_schedules", CatalogGenerator.snakeCase("getSiteScanSchedules"))
        assertEquals("get_vulnerability_references_1", CatalogGenerator.snakeCase("getVulnerabilityReferences_1"))
        assertEquals("start_http_scan", CatalogGenerator.snakeCase("startHTTPScan"))
        assertEquals("a_b", CatalogGenerator.snakeCase("__a--b__"))
    }

    private fun spec(paths: JsonObject, schemas: JsonObject = JsonObject(emptyMap())): JsonObject = buildJsonObject {
        putJsonObject("info") { put("title", "T"); put("version", "9") }
        put("paths", paths)
        putJsonObject("components") { put("schemas", schemas) }
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
            assertFailsWith<CatalogGenerator.CatalogGenerationException> { CatalogGenerator.generate(dir) }
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
