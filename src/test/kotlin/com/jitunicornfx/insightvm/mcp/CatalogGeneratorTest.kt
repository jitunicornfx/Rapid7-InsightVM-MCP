package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogGenerator
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CatalogGeneratorTest {

    private val specs: Path = Path.of("specs")
    private val committed: Path = Path.of("src/main/resources/catalog")

    @Test
    fun `generated catalogs are byte-identical to the committed ones`() {
        assertEquals(emptyList(), CatalogGenerator.drift(specs, committed))
    }

    @Test
    fun `generated catalogs pass the runtime loader and match the bundled resources`() {
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
}
