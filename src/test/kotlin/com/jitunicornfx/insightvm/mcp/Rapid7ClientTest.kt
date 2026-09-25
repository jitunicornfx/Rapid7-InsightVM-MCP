package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.testutil.MeteredBody
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CLOUD
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CONSOLE
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Rapid7ClientTest {

    private fun engine(status: HttpStatusCode = HttpStatusCode.OK, body: String = "{}", contentType: String = "application/json", bytes: ByteArray? = null) =
        MockEngine { _ ->
            if (bytes != null) respond(bytes, status, headersOf(HttpHeaders.ContentType, contentType))
            else respond(body, status, headersOf(HttpHeaders.ContentType, contentType))
        }

    @Test
    fun `console requests carry basic auth, 2fa token, accept and query`() = runBlocking {
        val e = engine()
        val config = testConfig(console = TEST_CONSOLE.copy(twoFactorToken = "otp"))
        val client = Rapid7Client(config, consoleEngine = e, cloudEngine = engine())
        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/api/3/sites", query = mapOf("sort" to listOf("a", "b"), "page" to listOf("0")))
        assertTrue(r.ok)
        assertEquals(200, r.status)
        val req = e.requestHistory.single()
        assertEquals("https://console.test:3780/api/3/sites?sort=a&sort=b&page=0", req.url.toString())
        assertEquals("Basic YXBpLXVzZXI6czNjcmV0", req.headers[HttpHeaders.Authorization])
        assertEquals("otp", req.headers["Token"])
        assertEquals("application/json", req.headers[HttpHeaders.Accept])
        assertNull(req.headers["X-Api-Key"])
        client.close()
    }

    @Test
    fun `cloud requests carry the api key and json body`() = runBlocking {
        val e = engine()
        val client = Rapid7Client(testConfig(), consoleEngine = engine(), cloudEngine = e)
        client.request(ApiFamily.CLOUD, HttpMethod.Post, "/v4/integration/assets", jsonBody = buildJsonObject { put("asset", "x") })
        val req = e.requestHistory.single()
        assertEquals("https://us.api.insight.rapid7.com/vm/v4/integration/assets", req.url.toString())
        assertEquals(TEST_CLOUD.apiKey, req.headers["X-Api-Key"])
        assertNull(req.headers["Token"])
        val body = req.body as TextContent
        assertEquals("""{"asset":"x"}""", body.text)
        assertEquals(ContentType.Application.Json, body.contentType.withoutParameters())
        client.close()
    }

    @Test
    fun `raw bodies use the given content type`() = runBlocking {
        val e = engine(contentType = "text/plain", body = "ok")
        val client = Rapid7Client(testConfig(), consoleEngine = e, cloudEngine = engine())
        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Post, "/api/3/administration/commands", rawBody = "help", rawContentType = ContentType.Text.Plain, accept = ContentType.Text.Plain)
        assertEquals("ok", r.text)
        assertNull(r.bytes)
        val body = e.requestHistory.single().body as TextContent
        assertEquals("help", body.text)
        assertEquals(ContentType.Text.Plain, body.contentType.withoutParameters())
        assertEquals("text/plain", e.requestHistory.single().headers[HttpHeaders.Accept])
        client.close()
    }

    @Test
    fun `unconfigured family is refused before any request`() = runBlocking {
        val client = Rapid7Client(testConfig(console = null), cloudEngine = engine())
        assertFailsWith<IllegalStateException> { client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/x") }
        assertFailsWith<IllegalStateException> { client.baseUrlFor(ApiFamily.CONSOLE) }
        assertEquals("https://us.api.insight.rapid7.com/vm", client.baseUrlFor(ApiFamily.CLOUD))
        client.close()
    }

    @Test
    fun `path must be absolute`() = runBlocking {
        val client = Rapid7Client(testConfig(), consoleEngine = engine(), cloudEngine = engine())
        assertFailsWith<IllegalArgumentException> { client.request(ApiFamily.CONSOLE, HttpMethod.Get, "api/3/sites") }
        client.close()
    }

    @Test
    fun `redirects are not followed`() = runBlocking {
        val e = MockEngine { respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "https://evil.example/")) }
        val client = Rapid7Client(testConfig(), consoleEngine = e, cloudEngine = engine())
        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/api/3/sites")
        assertEquals(302, r.status)
        assertFalse(r.ok)
        assertEquals(1, e.requestHistory.size)
        client.close()
    }

    @Test
    fun `binary responses are returned as bytes and textual ones as text`() = runBlocking {
        val zip = byteArrayOf(0x50, 0x4B, 3, 4)
        val client = Rapid7Client(testConfig(), consoleEngine = engine(bytes = zip, contentType = "application/zip"), cloudEngine = engine(body = "<x/>", contentType = "application/xml; charset=ISO-8859-1"))
        val bin = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/api/3/administration/logs")
        assertContentEquals(zip, bin.bytes)
        assertNull(bin.text)
        val xml = client.request(ApiFamily.CLOUD, HttpMethod.Get, "/admin/health")
        assertEquals("<x/>", xml.text)
        assertNull(xml.bytes)
        client.close()
    }

    @Test
    fun `response bodies are capped`() = runBlocking {
        val big = "y".repeat(5000)
        val client = Rapid7Client(testConfig(maxResponseBytes = 100), consoleEngine = engine(body = big, contentType = "text/plain"), cloudEngine = engine(body = "z".repeat(100), contentType = "text/plain"))
        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/x")
        assertTrue(r.truncated)
        assertEquals(100, r.text!!.length)
        assertEquals(100, r.limitBytes)
        val exact = client.request(ApiFamily.CLOUD, HttpMethod.Get, "/x")
        assertFalse(exact.truncated)
        assertEquals(100, exact.text!!.length)
        client.close()
    }

    /**
     * Regression: request() had Ktor save the whole body to memory before readCapped saw a byte, so
     * the cap only trimmed what the heap had already paid for — a console streaming a large log
     * download or report was an OutOfMemoryError. Read as a stream, the cap stops the transfer.
     */
    @Test
    fun `the response cap stops the transfer rather than trimming a buffered body`() = runBlocking {
        val limit = 1L * 1024 * 1024
        val body = MeteredBody(totalBytes = 64L * 1024 * 1024)
        val e = MockEngine { respond(body.channel(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/octet-stream")) }
        val client = Rapid7Client(testConfig(maxResponseBytes = limit), consoleEngine = e, cloudEngine = engine())

        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/api/3/administration/logs")

        assertTrue(r.truncated)
        assertEquals(limit.toInt(), r.bytes!!.size)
        assertTrue(body.wasStreamed(kept = limit), "${body.produced.get()} of ${body.totalBytes} bytes were pulled to return $limit")
        client.close()
    }

    @Test
    fun `readCapped edge cases`() = runBlocking {
        val (empty, t0) = Rapid7Client.readCapped(ByteReadChannel(ByteArray(0)), 10)
        assertEquals(0, empty.size); assertFalse(t0)
        val (small, t1) = Rapid7Client.readCapped(ByteReadChannel("abc".toByteArray()), 10)
        assertEquals("abc", small.toString(Charsets.UTF_8)); assertFalse(t1)
        val (cut, t2) = Rapid7Client.readCapped(ByteReadChannel(ByteArray(100_000) { 1 }), 1000)
        assertEquals(1000, cut.size); assertTrue(t2)
    }

    @Test
    fun `readCapped does not overflow on a limit above Int MAX_VALUE`() = runBlocking {
        // (limit - out.size()) narrowed to Int wraps negative above 2^31 and throws on write().
        val (bytes, truncated) = Rapid7Client.readCapped(ByteReadChannel(ByteArray(50_000) { 7 }), 3_000_000_000L)
        assertEquals(50_000, bytes.size)
        assertFalse(truncated)
    }

    @Test
    fun `trimIncompleteUtf8 drops only a split trailing sequence`() {
        // One 2-byte, one 3-byte and one 4-byte sequence, cut at every position inside each.
        for (sample in listOf("eé", "e€", "e😀")) {
            val full = sample.toByteArray(Charsets.UTF_8)
            assertContentEquals(full, Rapid7Client.trimIncompleteUtf8(full), "complete input is untouched")
            for (cut in 2 until full.size) {
                val trimmed = Rapid7Client.trimIncompleteUtf8(full.copyOf(cut)).toString(Charsets.UTF_8)
                assertEquals("e", trimmed, "split at $cut of $sample")
                assertFalse(trimmed.contains('�'))
            }
        }
        assertContentEquals(ByteArray(0), Rapid7Client.trimIncompleteUtf8(ByteArray(0)))
        assertContentEquals("abc".toByteArray(), Rapid7Client.trimIncompleteUtf8("abc".toByteArray()))
        // A continuation run longer than any sequence is left alone rather than eaten.
        val stray = ByteArray(6) { 0x80.toByte() }
        assertContentEquals(stray, Rapid7Client.trimIncompleteUtf8(stray))
    }

    @Test
    fun `a truncated body never ends in a replacement character`() = runBlocking {
        // The cap lands mid-euro-sign: 3 bytes of it, capped at 2.
        val body = "aa€".toByteArray(Charsets.UTF_8)
        val e = MockEngine { respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }
        val client = Rapid7Client(testConfig(maxResponseBytes = 4), consoleEngine = e, cloudEngine = engine())
        val r = client.request(ApiFamily.CONSOLE, HttpMethod.Get, "/x")
        assertTrue(r.truncated)
        assertEquals("aa", r.text)
        client.close()
    }

    @Test
    fun `isTextual classification`() {
        assertTrue(Rapid7Client.isTextual(ContentType.parse("text/html")))
        assertTrue(Rapid7Client.isTextual(ContentType.parse("application/json")))
        assertTrue(Rapid7Client.isTextual(ContentType.parse("application/problem+json")))
        assertTrue(Rapid7Client.isTextual(ContentType.parse("application/javascript")))
        assertTrue(Rapid7Client.isTextual(ContentType.parse("application/x-www-form-urlencoded")))
        assertFalse(Rapid7Client.isTextual(ContentType.parse("application/zip")))
        assertFalse(Rapid7Client.isTextual(ContentType.parse("image/png")))
    }

    @Test
    fun `real OkHttp engines are constructed for both families`() {
        // No network call is made; this covers the production engine branch including TLS customisation.
        val warnings = mutableListOf<String>()
        val caPath = java.nio.file.Paths.get(javaClass.getResource("/tls/test-ca.pem")!!.toURI()).toString()
        val withCa = Rapid7Client(testConfig(console = TEST_CONSOLE.copy(caCertPath = caPath)), warn = warnings::add)
        withCa.close()
        assertTrue(warnings.isEmpty())
        val insecure = Rapid7Client(testConfig(console = TEST_CONSOLE.copy(insecureTls = true)), warn = warnings::add)
        insecure.close()
        assertEquals(listOf(TlsSupport.INSECURE_BANNER), warnings)
        Rapid7Client(testConfig()).close()
    }
}
