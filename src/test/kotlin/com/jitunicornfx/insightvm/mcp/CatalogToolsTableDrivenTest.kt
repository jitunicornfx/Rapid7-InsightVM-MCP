package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogOp
import com.jitunicornfx.insightvm.mcp.testutil.McpTestHarness
import com.jitunicornfx.insightvm.mcp.testutil.SchemaExampleSynthesizer
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CLOUD
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CONSOLE
import com.jitunicornfx.insightvm.mcp.testutil.mcpHarness
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.content.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.TestInstance
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Drives EVERY catalog operation through a real MCP client/server pair: arguments are synthesized
 * from the tool's own input schema, the call must succeed, and the HTTP request the tool produced
 * must match the catalog entry (method, path substitution, query parameters, body, auth, accept).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CatalogToolsTableDrivenTest {

    private lateinit var harness: McpTestHarness
    private lateinit var toolsByName: Map<String, io.modelcontextprotocol.kotlin.sdk.types.Tool>

    @BeforeAll
    fun start() = runBlocking {
        // Both gates open, so every catalog operation is registered and exercised.
        harness = mcpHarness(testConfig(filter = ToolFilter(allowAdminCommands = true, allowSecretTools = true)))
        toolsByName = harness.listTools().associateBy { it.name }
    }

    @AfterAll
    fun stop() = runBlocking { harness.client.close() }

    private fun allOps(): List<Pair<ApiFamily, CatalogOp>> =
        TEST_CATALOGS.flatMap { (family, catalog) -> catalog.ops.map { family to it } }

    @TestFactory
    fun `every catalog operation round-trips through MCP`(): List<DynamicTest> = allOps().map { (family, op) ->
        DynamicTest.dynamicTest("${family.id}:${op.name}") { runBlocking { exercise(family, op) } }
    }

    private suspend fun exercise(family: ApiFamily, op: CatalogOp) {
        val tool = assertNotNull(toolsByName[op.name], "tool ${op.name} not registered")
        assertEquals(op.readOnly, tool.annotations?.readOnlyHint, "readOnlyHint for ${op.name}")
        if (op.readOnly) assertNull(tool.annotations?.destructiveHint) else assertEquals(op.destructive, tool.annotations?.destructiveHint)
        // MCP gives idempotentHint meaning only on a tool that is not read-only. PUT and DELETE are
        // idempotent by HTTP semantics; a POST may create a second record or start a second scan.
        assertEquals(
            if (op.readOnly) null else op.method in setOf("PUT", "DELETE"),
            tool.annotations?.idempotentHint,
            "idempotentHint for ${op.name}",
        )
        assertTrue(tool.description!!.contains("${op.method} ${op.path}"), "description names the route")

        val props = tool.inputSchema.properties ?: JsonObject(emptyMap())
        val args = SchemaExampleSynthesizer.argsFor(props)
        val before = harness.requests.size
        val result = harness.callJson(op.name, args)
        val text = harness.text(result)

        assertFalse(result.isError == true, "${op.name} returned error: ${text.take(300)}")
        assertTrue(text.contains(UNTRUSTED_BEGIN) && text.endsWith(UNTRUSTED_END), "${op.name} output is fenced")
        assertEquals(before + 1, harness.requests.size, "${op.name} made exactly one request")

        val request = harness.lastRequest
        assertEquals(HttpMethod.parse(op.method), request.method)

        // Path: every placeholder replaced by the synthesized value.
        val expectedPath = op.params.filter { it.isPath }.fold(op.path) { acc, p ->
            acc.replace("{${p.name}}", expectedWire(p.schema))
        }
        val basePath = when (family) {
            ApiFamily.CONSOLE -> ""
            ApiFamily.CLOUD -> "/vm"
        }
        assertEquals(basePath + expectedPath, request.url.encodedPath, "${op.name} path")
        assertEquals(
            when (family) {
                ApiFamily.CONSOLE -> "console.test"
                ApiFamily.CLOUD -> "us.api.insight.rapid7.com"
            },
            request.url.host,
        )

        // Query: one entry per declared query parameter with the synthesized value.
        for (p in op.params.filter { it.isQuery }) {
            val values = request.url.parameters.getAll(p.name)
            assertNotNull(values, "${op.name} query param ${p.name} present")
            val schema = if (p.array) (p.schema["items"] as JsonObject) else p.schema
            assertEquals(listOf(expectedWire(schema)), values, "${op.name} query ${p.name}")
        }
        val declared = op.params.filter { it.isQuery }.map { it.name }.toSet()
        assertEquals(declared, request.url.parameters.names(), "${op.name} sends only declared query params")

        // Body.
        val body = request.body as? TextContent
        if (op.body == null) {
            assertNull(body?.text?.takeIf { it.isNotEmpty() }, "${op.name} must not send a body")
        } else {
            assertNotNull(body, "${op.name} sends a body")
            assertEquals(op.body!!.contentType, body.contentType.withoutParameters().toString())
            if (op.body!!.isJson) {
                val sent = JsonCodec.compact.parseToJsonElement(body.text)
                val expectedType = (op.body!!.schema["type"] as? JsonPrimitive)?.content ?: "object"
                when (expectedType) {
                    "array" -> assertTrue(sent is JsonArray)
                    "object" -> assertTrue(sent is JsonObject)
                }
            }
        }

        // Auth + accept.
        when (family) {
            ApiFamily.CONSOLE -> {
                val expected = "Basic " + Base64.getEncoder().encodeToString("${TEST_CONSOLE.username}:${TEST_CONSOLE.password}".toByteArray())
                assertEquals(expected, request.headers[HttpHeaders.Authorization])
                assertNull(request.headers["X-Api-Key"])
            }
            ApiFamily.CLOUD -> {
                assertEquals(TEST_CLOUD.apiKey, request.headers["X-Api-Key"])
                assertNull(request.headers[HttpHeaders.Authorization])
            }
        }
        val accept = request.headers[HttpHeaders.Accept]!!
        when {
            op.responses.binary -> assertEquals("*/*", accept, "${op.name} is binary")
            op.responses.success == "text/html" -> assertEquals("text/html", accept)
            op.responses.success == "text/plain" -> assertEquals("text/plain", accept)
            else -> assertEquals("application/json", accept, "${op.name} (${op.responses.success})")
        }
    }

    private fun expectedWire(schema: JsonObject): String {
        (schema["enum"] as? JsonArray)?.firstOrNull()?.let { return (it as JsonPrimitive).content }
        return when ((schema["type"] as? JsonPrimitive)?.content) {
            "integer" -> SchemaExampleSynthesizer.INT_EXAMPLE.toString()
            "number" -> "1.5"
            "boolean" -> "true"
            else -> SchemaExampleSynthesizer.STRING_EXAMPLE
        }
    }

    @TestFactory
    fun `tool list matches the catalog exactly`(): List<DynamicTest> = listOf(
        DynamicTest.dynamicTest("counts") {
            val apiTools = toolsByName.keys -
                setOf("insightvm_server_info", "insightvm_list_tool_groups", "insightvm_search_criteria", "insightvm_export_to_file")
            assertEquals(allOps().map { it.second.name }.toSet(), apiTools)
            assertEquals(330, TEST_CATALOGS.getValue(ApiFamily.CONSOLE).ops.size)
            assertEquals(13, TEST_CATALOGS.getValue(ApiFamily.CLOUD).ops.size)
        },
        DynamicTest.dynamicTest("names are valid and unique") {
            val names = allOps().map { it.second.name }
            assertEquals(names.size, names.toSet().size)
            names.forEach { assertTrue(CatalogLoader.TOOL_NAME_PATTERN.matches(it), it) }
        },
        DynamicTest.dynamicTest("input schemas declare required fields that exist") {
            toolsByName.values.forEach { tool ->
                tool.inputSchema.required?.forEach { r -> assertTrue(r in tool.inputSchema.properties!!.jsonObject, "${tool.name}.$r") }
            }
        },
    )
}
