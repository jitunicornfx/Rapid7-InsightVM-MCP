package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.CatalogTools
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.contentType
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The `--http` transport as it really runs: a bound socket, the real guard and the real MCP routes
 * that [buildHttpRuntime] mounts. The guard has its own unit tests; these show how it and the SDK's
 * routes behave together, which no test of either alone can.
 */
class HttpRuntimeTest {

    private val token = "0123456789abcdef0123456789abcdef"

    /** One API tool (the Root tag's), so building a server per session costs little. */
    private val config = testConfig(filter = ToolFilter(tags = setOf("Root")))
        .copy(httpAuthToken = token, httpAllowedOrigins = listOf("https://ui.example"))

    private val initialize =
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"""

    private var runtime: HttpRuntime? = null
    private val http = HttpClient(OkHttp) { expectSuccess = false }

    @BeforeTest
    fun freshStatus() {
        UpdateStatus.reset()
    }

    @AfterTest
    fun stop() {
        runtime?.let { it.engine.stop(100, 500); it.shutdown() }
        http.close()
        UpdateStatus.reset()
    }

    private fun mockClient(config: Config) = Rapid7Client(
        config,
        consoleEngine = MockEngine { respond("""{"ok":true}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
        cloudEngine = MockEngine { respond("""{"ok":true}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
    )

    /** [update] is what the update check reports: no GitHub call from a unit test. */
    private fun checkReporting(update: UpdateChecker.Result?): CoroutineScope.(Config) -> Deferred<UpdateChecker.Result>? =
        { update?.let { CompletableDeferred(it) } }

    /** Run [block] with stderr silenced: the runtime logs its startup there. */
    private fun <T> quietly(block: () -> T): T {
        val realErr = System.err
        System.setErr(PrintStream(ByteArrayOutputStream(), true, "UTF-8"))
        return try {
            block()
        } finally {
            System.setErr(realErr)
        }
    }

    /** Start on an ephemeral loopback port and return its base URL. */
    private fun start(
        update: UpdateChecker.Result? = null,
        notifyGraceMillis: Long = HTTP_NOTIFY_GRACE_MILLIS,
        maxLiveSessions: Int = HTTP_MAX_LIVE_SESSIONS,
    ): String = runBlocking {
        val built = quietly {
            buildHttpRuntime(mockClient(config), config, "127.0.0.1", 0, checkReporting(update), notifyGraceMillis, maxLiveSessions)
        }
        runtime = built
        built.engine.start(wait = false)
        val port = withTimeout(10_000) { built.engine.engine.resolvedConnectors().first().port }
        "http://127.0.0.1:$port"
    }

    private fun HttpRequestBuilder.mcpHeaders(session: String? = null, origin: String? = null) {
        header(HttpHeaders.Authorization, "Bearer $token")
        header(HttpHeaders.Accept, "application/json, text/event-stream")
        session?.let { header("Mcp-Session-Id", it) }
        origin?.let { header(HttpHeaders.Origin, it) }
    }

    /** Initialize a Streamable HTTP session, say `initialized`, and return the session id. */
    private suspend fun openSession(base: String): String {
        val init = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders()
            contentType(ContentType.Application.Json)
            setBody(initialize)
        }
        assertEquals(HttpStatusCode.OK, init.status, init.bodyAsText())
        val session = assertNotNull(init.headers["Mcp-Session-Id"])
        init.bodyAsText()
        http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders(session)
            contentType(ContentType.Application.Json)
            setBody("""{"jsonrpc":"2.0","method":"notifications/initialized"}""")
        }.bodyAsText()
        return session
    }

    /** Send one JSON-RPC request on [session]; returns the status and the body. */
    private suspend fun rpc(base: String, session: String, body: String): Pair<HttpStatusCode, String> {
        val response = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders(session)
            contentType(ContentType.Application.Json)
            setBody(body)
        }
        return response.status to response.bodyAsText()
    }

    private suspend fun listToolsStatus(base: String, session: String): HttpStatusCode =
        rpc(base, session, """{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""").first

    /** Poll [probe] until it returns [expected] or [timeoutMillis] passes; returns the last value seen. */
    private suspend fun <T> eventually(expected: T, timeoutMillis: Long = 10_000, probe: suspend () -> T): T {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var last = probe()
        while (last != expected && System.currentTimeMillis() < deadline) {
            delay(50)
            last = probe()
        }
        return last
    }

    private val live: Int get() = runtime!!.sessions.liveCount

    // ------------------------------------------------------------------------- session cap

    /**
     * Regression: every sessionless POST built a Server that the SDK dropped only on DELETE, which
     * most clients never send, so a long-running --http server grew by one Server per reconnect.
     */
    @Test
    fun `sessions a client abandons without DELETE are closed once the cap is passed, oldest first`() = runBlocking {
        val base = start(maxLiveSessions = 2)
        val first = openSession(base)
        val second = openSession(base)
        assertEquals(2, live)

        val third = openSession(base)
        // The oldest is closed and the SDK forgets its id: the client is told 404, and starts again.
        assertEquals(HttpStatusCode.NotFound, eventually(HttpStatusCode.NotFound) { listToolsStatus(base, first) })
        assertEquals(HttpStatusCode.OK, listToolsStatus(base, second))
        assertEquals(HttpStatusCode.OK, listToolsStatus(base, third))
        assertEquals(2, live)

        // Refusing new sessions instead would have locked out the returning client for good.
        val again = openSession(base)
        assertEquals(HttpStatusCode.OK, listToolsStatus(base, again))
        assertEquals(HttpStatusCode.NotFound, eventually(HttpStatusCode.NotFound) { listToolsStatus(base, second) })
        assertEquals(2, live)
    }

    /**
     * Regression: the SDK builds a Server for every sessionless POST before it reads the body, so a
     * probe or a buggy client posting anything but initialize took a slot too — and past the cap each
     * one closed the oldest REAL session, cancelling its calls. A Server that never initialized serves
     * no client, so it now goes first; memory stays bounded all the same.
     */
    @Test
    fun `sessionless POSTs that never initialize cannot evict a live session`() = runBlocking {
        val base = start(maxLiveSessions = 2)
        val kept = openSession(base)
        repeat(5) {
            val stray = http.post("$base$STREAMABLE_HTTP_PATH") {
                mcpHeaders()
                contentType(ContentType.Application.Json)
                setBody("""{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}""")
            }
            assertTrue(stray.status.value in 400..499, "a sessionless call that is not initialize is refused: ${stray.status}")
            stray.bodyAsText()
        }
        // The eviction is asynchronous, so give a wrong one the time to happen before judging.
        assertEquals(HttpStatusCode.OK, eventually(HttpStatusCode.NotFound, timeoutMillis = 2_000) { listToolsStatus(base, kept) })
        assertTrue(live <= 2, "still bounded: $live")

        // A real client still gets in, and it is a stray that makes room, not the live session.
        val second = openSession(base)
        assertEquals(HttpStatusCode.OK, eventually(HttpStatusCode.NotFound, timeoutMillis = 2_000) { listToolsStatus(base, kept) })
        assertEquals(HttpStatusCode.OK, listToolsStatus(base, second))
        assertEquals(2, live)
    }

    @Test
    fun `a session the client ends with DELETE stops counting at once`() = runBlocking {
        val base = start(maxLiveSessions = 2)
        val kept = openSession(base)
        val ended = openSession(base)
        val deleted = http.delete("$base$STREAMABLE_HTTP_PATH") { mcpHeaders(ended) }
        assertEquals(HttpStatusCode.OK, deleted.status, deleted.bodyAsText())
        assertEquals(1, eventually(1) { live })

        // So a new session fits beside the one still in use, and closes nothing.
        openSession(base)
        assertEquals(2, live)
        assertEquals(HttpStatusCode.OK, listToolsStatus(base, kept))
    }

    @Test
    fun `a legacy stream whose server the cap closes ends, and its message endpoint is gone`() = runBlocking {
        val base = start(maxLiveSessions = 1)
        val lines = Channel<String?>(Channel.UNLIMITED)
        val stream = async {
            http.prepareGet("$base$LEGACY_SSE_PATH") { mcpHeaders() }.execute { response ->
                val channel = response.bodyAsChannel()
                while (true) {
                    val line = channel.readLine()
                    lines.send(line)
                    if (line == null) break
                }
            }
        }
        try {
            val endpoint = withTimeout(10_000) { legacyEndpoint(lines) }
            assertEquals(1, live)

            openSession(base) // passes the cap of one: the legacy server is the oldest
            // The stream ends: the client learns at once that its session is gone.
            withTimeout(10_000) {
                var ended = false
                while (!ended) ended = lines.receive() == null
            }
            val post = http.post("$base$endpoint") {
                mcpHeaders()
                contentType(ContentType.Application.Json)
                setBody(initialize)
            }
            assertEquals(HttpStatusCode.NotFound, post.status)
            assertEquals(1, live)
        } finally {
            stream.cancel()
        }
    }

    /** Read SSE lines until the legacy `endpoint` event, and return its path. */
    private suspend fun legacyEndpoint(lines: Channel<String?>): String {
        while (true) {
            val line = lines.receive() ?: error("the stream ended before announcing its endpoint")
            if (line.startsWith("data:") && "sessionId=" in line) return line.removePrefix("data:").trim()
        }
    }

    @Test
    fun `a runtime built without naming a cap or a grace period uses the production ones`() {
        // The other tests pass their own, so a default that never evicts, or a grace of 0 (the very
        // bug it fixes), would go unnoticed.
        val built = quietly { buildHttpRuntime(mockClient(config), config, "127.0.0.1", 0, checkReporting(null)) }
        try {
            assertEquals(HTTP_MAX_LIVE_SESSIONS, built.sessions.maxLive)
            assertEquals(HTTP_NOTIFY_GRACE_MILLIS, built.notifyGraceMillis)
        } finally {
            built.shutdown()
        }
        assertTrue(HTTP_MAX_LIVE_SESSIONS in 8..256, "was $HTTP_MAX_LIVE_SESSIONS")
        assertTrue(HTTP_NOTIFY_GRACE_MILLIS in 1_000L..5_000L, "long enough to matter, short enough not to be noticed")
    }

    // ------------------------------------------------------------------------- update notice

    private val available = UpdateChecker.Result(updateAvailable = true, currentVersion = "0.2.1", latestVersion = "9.9.9")

    /**
     * Drive Streamable HTTP by hand so the moment the client opens its event stream is under the
     * test's control: initialize, say `initialized`, wait [openStreamAfterMillis], THEN open the GET
     * stream and report whether the update notice turns up on it. The SDK's own Kotlin client opens
     * its stream fast enough to win the race, so a test through it passes with or without a fix.
     */
    private suspend fun noticeArrives(base: String, openStreamAfterMillis: Long, waitMillis: Long = 4_000): Boolean {
        val session = openSession(base)
        delay(openStreamAfterMillis)
        return withTimeoutOrNull(waitMillis) {
            http.prepareGet("$base$STREAMABLE_HTTP_PATH") { mcpHeaders(session) }.execute { response ->
                val channel = response.bodyAsChannel()
                var found = false
                while (!found) {
                    val line = channel.readLine() ?: break
                    if ("latest_version" in line && "9.9.9" in line) found = true
                }
                found
            }
        } ?: false
    }

    /**
     * Measured against SDK 0.15.0, not assumed: a server-initiated message with no open stream to
     * travel on is DROPPED, not queued. If this starts failing because the notice ARRIVES, the SDK has
     * begun queueing and [HTTP_NOTIFY_GRACE_MILLIS] can go.
     */
    @Test
    fun `a notice sent before the client opens its stream is lost, which is what the grace period is for`() = runBlocking {
        val base = start(update = available, notifyGraceMillis = 0)
        assertFalse(noticeArrives(base, openStreamAfterMillis = 700))
    }

    @Test
    fun `a client that opens its stream a moment after initialized still gets the update notice`() = runBlocking {
        // The production grace period against a client that takes 500 ms.
        val base = start(update = available)
        assertTrue(noticeArrives(base, openStreamAfterMillis = 500), "the update notice was dropped")
    }

    @Test
    fun `server info answers with the update state whether or not the notice got through`() = runBlocking {
        val base = start(update = available, notifyGraceMillis = 0)
        assertFalse(noticeArrives(base, openStreamAfterMillis = 700), "premise: the push was lost")

        val session = openSession(base)
        val call = """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"${CatalogTools.SERVER_INFO_TOOL}","arguments":{}}}"""
        val (status, body) = rpc(base, session, call)
        assertEquals(HttpStatusCode.OK, status, body)
        // The answer is plain JSON or a server-sent event, as the transport chooses.
        val message = body.lines().map { it.removePrefix("data:").trim() }.singleOrNull { it.startsWith("{") && "\"id\":3" in it }
            ?: error("no answer to id 3 in: $body")
        val text = JsonCodec.compact.parseToJsonElement(message).jsonObject["result"]!!.jsonObject["content"]!!
            .jsonArray.single().jsonObject["text"]!!.jsonPrimitive.content
        val update = JsonCodec.compact.parseToJsonElement(text).jsonObject["update"]!!.jsonObject
        assertEquals("completed", update["check"]!!.jsonPrimitive.content)
        assertEquals("9.9.9", update["latestRelease"]!!.jsonPrimitive.content)
        assertEquals("true", update["updateAvailable"]!!.jsonPrimitive.content)
        // testConfig switches automatic installation off, and the status says so.
        assertEquals("disabled", update["install"]!!.jsonPrimitive.content)
        assertContains(update["summary"]!!.jsonPrimitive.content, "9.9.9")
    }

    // ------------------------------------------------------------------------- request size

    /**
     * [text] repeated to at least [bytes] bytes and sent with no Content-Length, so the client streams
     * it chunked and the guard's Content-Length check never sees a size. Written in slices, so nothing
     * is sized up front.
     */
    private fun chunked(text: String, bytes: Int = text.length): OutgoingContent = object : OutgoingContent.WriteChannelContent() {
        override val contentType = ContentType.Application.Json
        override val contentLength: Long? = null
        override suspend fun writeTo(channel: ByteWriteChannel) {
            val slice = text.toByteArray(Charsets.UTF_8)
            var written = 0
            while (written < bytes) {
                channel.writeFully(slice)
                written += slice.size
            }
        }
    }

    /**
     * The guard refuses a declared Content-Length over 4 MiB before the body is read, but a chunked
     * body declares none. SECURITY.md once listed that as an accepted gap on Streamable HTTP. Measured
     * against SDK 0.15.0 instead: both transports read a body under their own 4 MiB limit
     * (`maxRequestBodySize`, which the legacy route sets to the guard's own figure), and answer 413
     * past it. If this starts failing after an SDK upgrade, the gap is back and SECURITY.md is wrong.
     */
    @Test
    fun `a chunked body over the 4 MiB cap is refused on both transports`() = runBlocking {
        val base = start()
        // Just past the cap: the rest of the body fits in the socket buffers, so the client finishes
        // sending and reads the answer rather than racing the server's close.
        val over = HttpSecurity.DEFAULT_MAX_BODY_BYTES.toInt() + 16 * 1024
        val padding = " ".repeat(8 * 1024)

        // Premise: a chunked body under the cap reaches the SDK and opens a session.
        val accepted = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders()
            setBody(chunked(initialize))
        }
        assertEquals(HttpStatusCode.OK, accepted.status, accepted.bodyAsText())
        val session = assertNotNull(accepted.headers["Mcp-Session-Id"])

        val streamable = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders(session)
            setBody(chunked(padding, over))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, streamable.status)

        val lines = Channel<String?>(Channel.UNLIMITED)
        val stream = async {
            http.prepareGet("$base$LEGACY_SSE_PATH") { mcpHeaders() }.execute { response ->
                val channel = response.bodyAsChannel()
                while (true) {
                    val line = channel.readLine()
                    lines.send(line)
                    if (line == null) break
                }
            }
        }
        try {
            val endpoint = withTimeout(10_000) { legacyEndpoint(lines) }
            val legacy = http.post("$base$endpoint") {
                mcpHeaders()
                setBody(chunked(padding, over))
            }
            assertEquals(HttpStatusCode.PayloadTooLarge, legacy.status)
        } finally {
            stream.cancel()
        }
    }

    // ------------------------------------------------------------------------- browser origins

    /**
     * The SDK's transports carry their own Host/Origin check, localhost-only and on by default. Left
     * on, it answers 403 to an origin the operator explicitly allowed, after the guard and CORS have
     * both said yes: that is how the sibling server's allow-list came never to have worked. Here it is
     * switched off for Streamable HTTP and the legacy route is this server's own, so an allow-listed
     * origin must get all the way to a session on both, and an unlisted one no further than the guard.
     */
    @Test
    fun `an allow-listed browser origin reaches a session on both transports, and an unlisted one is refused`() = runBlocking {
        val base = start()

        val streamable = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders(origin = "https://ui.example")
            contentType(ContentType.Application.Json)
            setBody(initialize)
        }
        assertEquals(HttpStatusCode.OK, streamable.status, streamable.bodyAsText())
        assertEquals("https://ui.example", streamable.headers[HttpHeaders.AccessControlAllowOrigin])
        assertNotNull(streamable.headers["Mcp-Session-Id"])
        assertContains(streamable.bodyAsText(), SERVER_NAME)

        val refused = http.post("$base$STREAMABLE_HTTP_PATH") {
            mcpHeaders(origin = "https://evil.example")
            contentType(ContentType.Application.Json)
            setBody(initialize)
        }
        assertEquals(HttpStatusCode.Forbidden, refused.status)

        // Legacy HTTP+SSE: the stream announces the message endpoint, and initialize is POSTed there.
        val lines = Channel<String?>(Channel.UNLIMITED)
        val stream = async {
            http.prepareGet("$base$LEGACY_SSE_PATH") { mcpHeaders(origin = "https://ui.example") }.execute { response ->
                lines.send("status: ${response.status.value}")
                val channel = response.bodyAsChannel()
                while (true) {
                    val line = channel.readLine()
                    lines.send(line)
                    if (line == null) break
                }
            }
        }
        try {
            withTimeout(10_000) {
                assertEquals("status: 200", lines.receive())
                val endpoint = legacyEndpoint(lines)
                val refusedMessage = http.post("$base$endpoint") {
                    mcpHeaders(origin = "https://evil.example")
                    contentType(ContentType.Application.Json)
                    setBody(initialize)
                }
                assertEquals(HttpStatusCode.Forbidden, refusedMessage.status)

                val message = http.post("$base$endpoint") {
                    mcpHeaders(origin = "https://ui.example")
                    contentType(ContentType.Application.Json)
                    setBody(initialize)
                }
                assertEquals(HttpStatusCode.Accepted, message.status, message.bodyAsText())
                assertEquals("https://ui.example", message.headers[HttpHeaders.AccessControlAllowOrigin])
                // The initialize result arrives on the stream: the session was reached, not just the route.
                var answered = false
                while (!answered) {
                    val line = lines.receive() ?: error("the stream ended before the initialize result")
                    answered = line.startsWith("data:") && SERVER_NAME in line && "\"id\":1" in line
                }
            }
        } finally {
            stream.cancel()
        }

        val refusedStream = http.prepareGet("$base$LEGACY_SSE_PATH") { mcpHeaders(origin = "https://evil.example") }
            .execute { it.status }
        assertEquals(HttpStatusCode.Forbidden, refusedStream)
    }
}
