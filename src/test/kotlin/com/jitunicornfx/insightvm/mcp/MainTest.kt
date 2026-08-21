package com.jitunicornfx.insightvm.mcp

import com.github.ajalt.clikt.testing.test
import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CLOUD
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CONSOLE
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.defaultRequest
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MainTest {

    private data class Served(val transport: Transport, val host: String, val port: Int, val config: Config)

    private fun command(config: () -> Config = { testConfig() }): Pair<Rapid7InsightVmCommand, MutableList<Served>> {
        val served = mutableListOf<Served>()
        val cmd = Rapid7InsightVmCommand(config) { t, h, p, c -> served += Served(t, h, p, c) }
        return cmd to served
    }

    @Test
    fun `defaults are stdio on loopback 3072 with no filters`() {
        val (cmd, served) = command()
        val result = cmd.test("")
        assertEquals(0, result.statusCode, result.output)
        val s = served.single()
        assertEquals(Transport.STDIO, s.transport)
        assertEquals("127.0.0.1", s.host)
        assertEquals(3072, s.port)
        assertEquals(ToolFilter(), s.config.filter)
        assertTrue(s.config.updateCheckDisabled) // from testConfig
    }

    @Test
    fun `http options and filters reach serve as a merged filter`() {
        val (cmd, served) = command { testConfig().copy(filter = ToolFilter(tags = setOf("Site", "Asset"), excludeTags = setOf("User"))) }
        val result = cmd.test("--http --ip 127.0.0.1 --port 9999 --read-only --tags asset,Scan --tags Vulnerability --exclude-tags Tag --api console --tools 'get_*' --tools 'list_*' --no-auto-update")
        assertEquals(0, result.statusCode, result.output)
        val s = served.single()
        assertEquals(Transport.HTTP, s.transport)
        assertEquals(9999, s.port)
        val f = s.config.filter
        assertTrue(f.readOnly)
        assertEquals(setOf("asset"), f.tags) // intersection of env {Site, Asset} and cli {asset, Scan, Vulnerability}
        assertEquals(setOf("User", "Tag"), f.excludeTags)
        assertEquals(setOf(ApiFamily.CONSOLE), f.families)
        assertEquals(listOf("get_*", "list_*"), f.nameGlobs)
        assertFalse(f.allowAdminCommands)
        assertTrue(s.config.autoUpdateDisabled)
    }

    @Test
    fun `admin commands can be enabled from the cli or the environment`() {
        val (cli, servedCli) = command()
        assertEquals(0, cli.test("--allow-admin-commands").statusCode)
        assertTrue(servedCli.single().config.filter.allowAdminCommands)
        val (env, servedEnv) = command { testConfig(filter = ToolFilter(allowAdminCommands = true)) }
        assertEquals(0, env.test("").statusCode)
        assertTrue(servedEnv.single().config.filter.allowAdminCommands)
    }

    @Test
    fun `no-update-check implies no-auto-update`() {
        val (cmd, served) = command { testConfig().copy(updateCheckDisabled = false, autoUpdateDisabled = false) }
        assertEquals(0, cmd.test("--no-update-check").statusCode)
        assertTrue(served.single().config.updateCheckDisabled)
        assertTrue(served.single().config.autoUpdateDisabled)
        val (cmd2, served2) = command { testConfig().copy(updateCheckDisabled = false, autoUpdateDisabled = false) }
        assertEquals(0, cmd2.test("").statusCode)
        assertFalse(served2.single().config.updateCheckDisabled)
    }

    @Test
    fun `configuration errors exit 1 with a message`() {
        val (cmd, served) = command { throw IllegalStateException("boom missing var") }
        val result = cmd.test("")
        assertEquals(1, result.statusCode)
        assertContains(result.stderr, "Configuration error: boom missing var")
        assertTrue(served.isEmpty())
    }

    @Test
    fun `selecting an unconfigured api family exits 1`() {
        val (cmd, served) = command { testConfig(console = null) }
        val result = cmd.test("--api console")
        assertEquals(1, result.statusCode)
        assertContains(result.stderr, "not configured")
        assertTrue(served.isEmpty())
        val (ok, servedOk) = command { testConfig(console = null) }
        assertEquals(0, ok.test("--api cloud").statusCode)
        assertEquals(setOf(ApiFamily.CLOUD), servedOk.single().config.filter.families)
    }

    @Test
    fun `non-loopback http bind without a token is refused`() {
        val (cmd, served) = command()
        val result = cmd.test("--http --host 0.0.0.0")
        assertEquals(2, result.statusCode)
        assertContains(result.stderr, Config.ENV_MCP_AUTH_TOKEN)
        assertTrue(served.isEmpty())

        val (withToken, servedTok) = command { testConfig().copy(httpAuthToken = "t") }
        assertEquals(0, withToken.test("--http --host 0.0.0.0").statusCode)
        assertEquals("0.0.0.0", servedTok.single().host)

        val (stdioAnyHost, servedStdio) = command()
        assertEquals(0, stdioAnyHost.test("--stdio --host 0.0.0.0").statusCode)
        assertEquals(1, servedStdio.size)
    }

    @Test
    fun `help lists every switch and environment variable`() {
        val (cmd, _) = command()
        val help = cmd.test("--help").output
        listOf("--stdio", "--http", "--host", "--port", "3072", "--read-only", "--tags", "--exclude-tags", "--api", "--tools", "--allow-admin-commands", "--no-auto-update", "--no-update-check").forEach {
            assertContains(help, it)
        }
        listOf(Config.ENV_CONSOLE_URL, Config.ENV_API_KEY, Config.ENV_MCP_AUTH_TOKEN, Config.ENV_CONSOLE_CA_CERT, Config.ENV_READ_ONLY).forEach { assertContains(help, it) }
        assertContains(help, "aps2")
    }

    @Test
    fun `invalid option values are reported by clikt`() {
        val (cmd, served) = command()
        assertTrue(cmd.test("--port abc").statusCode != 0)
        assertTrue(cmd.test("--api saas").statusCode != 0)
        assertTrue(served.isEmpty())
    }

    @Test
    fun `startup banner names version, runtime, location and env variable names but never values`() {
        val banner = startupBanner(
            arrayOf("--stdio", "--read-only"),
            mapOf(Config.ENV_API_KEY to "super-secret-key", Config.ENV_REGION to "eu", "PATH" to "x"),
        )
        assertContains(banner, "$SERVER_NAME $SERVER_VERSION starting")
        assertContains(banner, "java ${System.getProperty("java.version")}")
        assertContains(banner, "location: ${runningLocation()}")
        assertContains(banner, "args: --stdio --read-only")
        assertContains(banner, "environment: ${Config.ENV_API_KEY}, ${Config.ENV_REGION}")
        assertFalse(banner.contains("super-secret-key"))
        assertFalse(banner.contains("PATH"))
        assertContains(startupBanner(emptyArray(), emptyMap()), "args: (none)")
        assertContains(startupBanner(emptyArray(), emptyMap()), "no INSIGHTVM_* variables set")
        assertTrue(runningLocation().isNotBlank())
    }

    // ----------------------------------------------------------------- real transports

    private fun mockClient(config: Config) = Rapid7Client(
        config,
        consoleEngine = MockEngine { respond("""{"ok":true}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
        cloudEngine = MockEngine { respond("""{"ok":true}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
    )

    private val initialize =
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"""

    @Test
    fun `stdio serves a session until stdin closes`() {
        val config = testConfig(filter = ToolFilter(tags = setOf("Root")))
        val input = PipedInputStream()
        val feed = PipedOutputStream(input)
        val captured = ByteArrayOutputStream()
        val out = PrintStream(captured, true, "UTF-8")
        val errBefore = System.err
        val errBuf = ByteArrayOutputStream()
        System.setErr(PrintStream(errBuf, true, "UTF-8"))
        try {
            val runner = Thread { runStdio(mockClient(config), config, out, input) }
            runner.start()
            feed.write((initialize + "\n").toByteArray())
            feed.write("""{"jsonrpc":"2.0","method":"notifications/initialized"}""".toByteArray() + "\n".toByteArray())
            feed.write("""{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""".toByteArray() + "\n".toByteArray())
            feed.write("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resources","arguments":{}}}""".toByteArray() + "\n".toByteArray())
            feed.flush()
            val deadline = System.currentTimeMillis() + 20_000
            while (System.currentTimeMillis() < deadline && !captured.toString("UTF-8").contains("\"id\":3")) Thread.sleep(50)
            feed.close()
            runner.join(20_000)
            assertFalse(runner.isAlive, "stdio runner must exit when stdin closes")
        } finally {
            System.setErr(errBefore)
        }
        val lines = captured.toString("UTF-8").lines().filter { it.isNotBlank() }.map { JsonCodec.compact.parseToJsonElement(it).jsonObject }
        val init = lines.first { it["id"]?.jsonPrimitive?.content == "1" }
        assertEquals(SERVER_NAME, init["result"]!!.jsonObject["serverInfo"]!!.jsonObject["name"]!!.jsonPrimitive.content)
        val tools = lines.first { it["id"]?.jsonPrimitive?.content == "2" }["result"]!!.jsonObject["tools"]!!.jsonArray
        assertEquals(1 + 2, tools.size) // Root tag has one op + two meta tools
        val call = lines.first { it["id"]?.jsonPrimitive?.content == "3" }["result"]!!.jsonObject
        assertContains(call["content"]!!.jsonArray.first().jsonObject["text"]!!.jsonPrimitive.content, "\"ok\": true")
        val err = errBuf.toString("UTF-8")
        assertContains(err, "Starting over stdio")
        assertContains(err, "registered 1/343 API tools")
        assertContains(err, "Update check disabled")
    }

    @Test
    fun `runServer over stdio redirects System out and serves`() {
        val config = testConfig(console = null, filter = ToolFilter(tags = setOf("Health")))
        val input = PipedInputStream()
        val feed = PipedOutputStream(input)
        val captured = ByteArrayOutputStream()
        val inBefore = System.`in`
        val outBefore = System.out
        val errBefore = System.err
        System.setIn(input)
        System.setOut(PrintStream(captured, true, "UTF-8"))
        System.setErr(PrintStream(ByteArrayOutputStream(), true, "UTF-8"))
        try {
            val runner = Thread { runServer(Transport.STDIO, "127.0.0.1", 3072, config) }
            runner.start()
            feed.write((initialize + "\n").toByteArray())
            feed.flush()
            val deadline = System.currentTimeMillis() + 20_000
            while (System.currentTimeMillis() < deadline && !captured.toString("UTF-8").contains("serverInfo")) Thread.sleep(50)
            // After redirection, a stray println must land on stderr, never on the protocol stream.
            println("stray diagnostic")
            feed.close()
            runner.join(20_000)
            assertFalse(runner.isAlive)
        } finally {
            System.setIn(inBefore)
            System.setOut(outBefore)
            System.setErr(errBefore)
        }
        val protocol = captured.toString("UTF-8")
        assertContains(protocol, "serverInfo")
        assertFalse(protocol.contains("stray diagnostic"))
    }

    @Test
    fun `http runtime serves streamable http and sse behind the security guard`() = runBlocking {
        val config = testConfig(filter = ToolFilter(tags = setOf("Root"))).copy(httpAuthToken = "tok", httpAllowedOrigins = listOf("https://ui.example"))
        val errBefore = System.err
        val errBuf = ByteArrayOutputStream()
        System.setErr(PrintStream(errBuf, true, "UTF-8"))
        val runtime = try {
            buildHttpRuntime(mockClient(config), config, "127.0.0.1", 0)
        } finally {
            System.setErr(errBefore)
        }
        runtime.engine.start(wait = false)
        val http = HttpClient(OkHttp) { expectSuccess = false }
        try {
            val port = withTimeout(10_000) { runtime.engine.engine.resolvedConnectors().first().port }
            val base = "http://127.0.0.1:$port"

            assertEquals(HttpStatusCode.Unauthorized, http.get("$base$STREAMABLE_HTTP_PATH").status)
            assertEquals(HttpStatusCode.Unauthorized, http.get("$base/sse").status)
            assertEquals(HttpStatusCode.Forbidden, http.post("$base$STREAMABLE_HTTP_PATH") {
                header(HttpHeaders.Authorization, "Bearer tok")
                header(HttpHeaders.Origin, "https://evil.example")
                contentType(ContentType.Application.Json)
                setBody(initialize)
            }.status)
            assertEquals(421, http.get("$base$STREAMABLE_HTTP_PATH") { header(HttpHeaders.Host, "rebind.example") ; header(HttpHeaders.Authorization, "Bearer tok") }.status.value)

            val init = http.post("$base$STREAMABLE_HTTP_PATH") {
                header(HttpHeaders.Authorization, "Bearer tok")
                header(HttpHeaders.Accept, "application/json, text/event-stream")
                contentType(ContentType.Application.Json)
                setBody(initialize)
            }
            assertEquals(HttpStatusCode.OK, init.status, init.bodyAsText())
            val sessionId = assertNotNull(init.headers["Mcp-Session-Id"], "streamable http assigns a session id")
            val body = init.bodyAsText()
            assertContains(body, SERVER_NAME)

            http.post("$base$STREAMABLE_HTTP_PATH") {
                header(HttpHeaders.Authorization, "Bearer tok")
                header("Mcp-Session-Id", sessionId)
                header(HttpHeaders.Accept, "application/json, text/event-stream")
                contentType(ContentType.Application.Json)
                setBody("""{"jsonrpc":"2.0","method":"notifications/initialized"}""")
            }
            val list = http.post("$base$STREAMABLE_HTTP_PATH") {
                header(HttpHeaders.Authorization, "Bearer tok")
                header("Mcp-Session-Id", sessionId)
                header(HttpHeaders.Accept, "application/json, text/event-stream")
                contentType(ContentType.Application.Json)
                setBody("""{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""")
            }
            assertEquals(HttpStatusCode.OK, list.status)
            val listBody = list.bodyAsText()
            assertContains(listBody, "\"resources\"")
            assertContains(listBody, "insightvm_server_info")

            val err = errBuf.toString("UTF-8")
            assertContains(err, "Starting over HTTP on 127.0.0.1:0")
            assertContains(err, "registered 1/343 API tools")
            assertFalse(err.contains("WARNING: no"))
        } finally {
            http.close()
            runtime.engine.stop(100, 500)
            runtime.shutdown()
        }
    }

    @Test
    fun `legacy sse transport works with the sdk client (which resolves the endpoint against the parent path)`() = runBlocking {
        val config = testConfig(console = null).copy(httpAuthToken = "tok")
        val errBefore = System.err
        System.setErr(PrintStream(ByteArrayOutputStream(), true, "UTF-8"))
        val runtime = try {
            buildHttpRuntime(mockClient(config), config, "127.0.0.1", 0)
        } finally {
            System.setErr(errBefore)
        }
        runtime.engine.start(wait = false)
        val http = HttpClient(OkHttp) {
            install(io.ktor.client.plugins.sse.SSE)
            defaultRequest { header(HttpHeaders.Authorization, "Bearer tok") }
        }
        try {
            val port = withTimeout(10_000) { runtime.engine.engine.resolvedConnectors().first().port }
            val transport = io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport(http, "http://127.0.0.1:$port$LEGACY_SSE_PATH")
            val mcp = io.modelcontextprotocol.kotlin.sdk.client.Client(io.modelcontextprotocol.kotlin.sdk.types.Implementation("sse-test", "0"))
            withTimeout(20_000) { mcp.connect(transport) }
            val tools = withTimeout(20_000) { mcp.listTools() }
            assertEquals(13 + 2, tools.tools.size)
            val result = withTimeout(20_000) { mcp.callTool("cloud_health", emptyMap()) }
            assertContains(harnessText(result), "\"ok\": true")
            mcp.close()

            // Unknown session / missing session id on the message endpoint.
            assertEquals(HttpStatusCode.NotFound, http.post("http://127.0.0.1:$port$LEGACY_SSE_PATH?sessionId=nope") { setBody("{}") }.status)
            assertEquals(HttpStatusCode.BadRequest, http.post("http://127.0.0.1:$port$LEGACY_SSE_PATH") { setBody("{}") }.status)
        } finally {
            http.close()
            runtime.engine.stop(100, 500)
            runtime.shutdown()
        }
    }

    private fun harnessText(result: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult): String =
        result.content.filterIsInstance<io.modelcontextprotocol.kotlin.sdk.types.TextContent>().joinToString("\n") { it.text }

    @Test
    fun `http runtime without a token warns and logs the large tool-set hint`() {
        val config = testConfig()
        val errBefore = System.err
        val errBuf = ByteArrayOutputStream()
        System.setErr(PrintStream(errBuf, true, "UTF-8"))
        val runtime = try {
            buildHttpRuntime(mockClient(config), config, "127.0.0.1", 0)
        } finally {
            System.setErr(errBefore)
        }
        runtime.shutdown()
        val err = errBuf.toString("UTF-8")
        assertContains(err, "WARNING: no ${Config.ENV_MCP_AUTH_TOKEN}")
        assertContains(err, "is a large set for some MCP clients")
        assertNull(Regex("s3cret|cloud-key").find(err))
    }
}
