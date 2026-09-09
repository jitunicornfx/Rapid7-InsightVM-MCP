package com.jitunicornfx.insightvm.mcp.testutil

import com.jitunicornfx.insightvm.mcp.BuiltServer
import com.jitunicornfx.insightvm.mcp.CloudConfig
import com.jitunicornfx.insightvm.mcp.Config
import com.jitunicornfx.insightvm.mcp.ConsoleConfig
import com.jitunicornfx.insightvm.mcp.JsonCodec
import com.jitunicornfx.insightvm.mcp.Rapid7Client
import com.jitunicornfx.insightvm.mcp.Region
import com.jitunicornfx.insightvm.mcp.SpoolStore
import com.jitunicornfx.insightvm.mcp.ToolFilter
import com.jitunicornfx.insightvm.mcp.buildInsightVmServer
import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ListToolsRequest
import io.modelcontextprotocol.kotlin.sdk.types.PaginatedRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.TextContent as McpText
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.io.path.createTempDirectory

val TEST_CONSOLE = ConsoleConfig(baseUrl = "https://console.test:3780", username = "api-user", password = "s3cret")
val TEST_CLOUD = CloudConfig(apiKey = "cloud-key", region = Region.US)

fun testConfig(
    console: ConsoleConfig? = TEST_CONSOLE,
    cloud: CloudConfig? = TEST_CLOUD,
    filter: ToolFilter = ToolFilter(),
    maxResponseBytes: Long = Config.DEFAULT_MAX_RESPONSE_BYTES,
    maxResultChars: Int = Config.DEFAULT_MAX_RESULT_CHARS,
): Config = Config(
    console = console,
    cloud = cloud,
    filter = filter,
    maxResponseBytes = maxResponseBytes,
    maxResultChars = maxResultChars,
    updateCheckDisabled = true,
    autoUpdateDisabled = true,
)

/** Canned response description for the mock engines. */
data class Canned(
    val status: HttpStatusCode = HttpStatusCode.OK,
    val body: String = "{}",
    val contentType: String = "application/json",
    val bytes: ByteArray? = null,
)

/**
 * A running in-process MCP client connected to a server whose tools use MockEngine-backed
 * [Rapid7Client]s (one engine per API family). Assert on [requests] (what the tools sent to the
 * API) and on the [CallToolResult] returned by [call].
 */
class McpTestHarness(
    val consoleEngine: MockEngine,
    val cloudEngine: MockEngine,
    val client: Client,
    val built: BuiltServer,
    private val capturedBodies: MutableList<String?>,
) {
    val requests: List<HttpRequestData> get() = consoleEngine.requestHistory + cloudEngine.requestHistory
    val lastRequest: HttpRequestData get() = requests.last()
    val lastBody: String? get() = capturedBodies.lastOrNull()

    fun lastBodyJson(): JsonElement = JsonCodec.compact.parseToJsonElement(lastBody!!)

    suspend fun call(name: String, args: Map<String, Any?> = emptyMap()): CallToolResult =
        client.callTool(name, args)

    suspend fun callJson(name: String, args: JsonObject): CallToolResult =
        client.callTool(name, args)

    suspend fun listTools(): List<Tool> {
        val all = mutableListOf<Tool>()
        var cursor: String? = null
        do {
            val page = client.listTools(ListToolsRequest(PaginatedRequestParams(cursor = cursor)))
            all += page.tools
            cursor = page.nextCursor
        } while (cursor != null)
        return all
    }

    fun text(result: CallToolResult): String =
        result.content.filterIsInstance<McpText>().joinToString("\n") { it.text }
}

/** Cached catalogs; loading + validating 500 KB of JSON per test would dominate the suite. */
val TEST_CATALOGS: Map<ApiFamily, Catalog> by lazy { CatalogLoader.loadAll() }

/**
 * Build a connected harness. [respond] decides the canned response for each request (default: a
 * JSON `{}` 200).
 */
suspend fun mcpHarness(
    config: Config = testConfig(),
    spool: SpoolStore = SpoolStore(createTempDirectory("harness-spool")),
    respond: (HttpRequestData) -> Canned = { Canned() },
): McpTestHarness {
    val bodies = mutableListOf<String?>()
    fun MockRequestHandleScope.answer(request: HttpRequestData): HttpResponseData {
        bodies += (request.body as? TextContent)?.text
        val canned = respond(request)
        return if (canned.bytes != null) {
            respond(content = canned.bytes, status = canned.status, headers = headersOf(HttpHeaders.ContentType, canned.contentType))
        } else {
            respond(content = canned.body, status = canned.status, headers = headersOf(HttpHeaders.ContentType, canned.contentType))
        }
    }
    val consoleEngine = MockEngine { answer(it) }
    val cloudEngine = MockEngine { answer(it) }

    val apiClient = Rapid7Client(config, consoleEngine = consoleEngine, cloudEngine = cloudEngine)
    val built = buildInsightVmServer(apiClient, config, TEST_CATALOGS.filterKeys { it in config.activeFamilies }, spool)

    val (clientTransport, serverTransport) = InMemoryTransport.createLinkedPair()
    val client = Client(Implementation("test-client", "1.0"))
    coroutineScope {
        launch { client.connect(clientTransport) }
        launch { built.server.createSession(serverTransport) }
    }
    return McpTestHarness(consoleEngine, cloudEngine, client, built, bodies)
}
