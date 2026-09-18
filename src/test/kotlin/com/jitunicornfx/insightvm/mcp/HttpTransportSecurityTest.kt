package com.jitunicornfx.insightvm.mcp

import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpTransportSecurityTest {

    private fun app(security: HttpSecurity, block: suspend (io.ktor.client.HttpClient) -> Unit) = testApplication {
        application {
            installTransportSecurity(security)
            routing {
                get("/mcp") { call.respondText("ok") }
                post("/mcp") { call.respondText("posted") }
            }
        }
        block(client)
    }

    private val loopbackNoToken = HttpSecurity("127.0.0.1", 3072, token = null, allowedOrigins = emptyList())
    private val loopbackToken = loopbackNoToken.copy(token = "s3cret-token")

    @Test
    fun `loopback without token allows plain local requests`() = app(loopbackNoToken) { c ->
        val r = c.get("/mcp") { header(HttpHeaders.Host, "localhost:3072") }
        assertEquals(HttpStatusCode.OK, r.status)
        assertEquals("ok", r.bodyAsText())
        assertEquals(HttpStatusCode.OK, c.get("/mcp") { header(HttpHeaders.Host, "127.0.0.1") }.status)
        assertEquals(HttpStatusCode.OK, c.get("/mcp") { header(HttpHeaders.Host, "[::1]:3072") }.status)
    }

    @Test
    fun `foreign Host header is rejected on loopback binds (DNS rebinding)`() = app(loopbackNoToken) { c ->
        val r = c.get("/mcp") { header(HttpHeaders.Host, "attacker.example:3072") }
        assertEquals(421, r.status.value)
    }

    @Test
    fun `Host header is not enforced on non-loopback binds`() = app(HttpSecurity("0.0.0.0", 3072, token = "t", allowedOrigins = emptyList())) { c ->
        val r = c.get("/mcp") {
            header(HttpHeaders.Host, "vm-mcp.corp.example:3072")
            header(HttpHeaders.Authorization, "Bearer t")
        }
        assertEquals(HttpStatusCode.OK, r.status)
    }

    @Test
    fun `browser origins are refused unless allow-listed`() = app(loopbackNoToken.copy(allowedOrigins = listOf("https://app.example:443", "*"))) { c ->
        assertEquals(HttpStatusCode.Forbidden, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Origin, "https://evil.example") }.status)
        assertEquals(HttpStatusCode.Forbidden, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Origin, "null") }.status)
        assertEquals(HttpStatusCode.Forbidden, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Origin, "ftp://app.example") }.status)
        val ok = c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Origin, "https://app.example") }
        assertEquals(HttpStatusCode.OK, ok.status)
        assertEquals("https://app.example", ok.headers[HttpHeaders.AccessControlAllowOrigin])
        // An allow-listed origin's host is also an acceptable Host header value.
        assertEquals(HttpStatusCode.OK, c.get("/mcp") { header(HttpHeaders.Host, "app.example") }.status)
    }

    @Test
    fun `cors preflight works for allowed origins and skips the bearer check`() = app(loopbackToken.copy(allowedOrigins = listOf("http://localhost:5173"))) { c ->
        val r = c.options("/mcp") {
            header(HttpHeaders.Host, "localhost:3072")
            header(HttpHeaders.Origin, "http://localhost:5173")
            header(HttpHeaders.AccessControlRequestMethod, "POST")
            header(HttpHeaders.AccessControlRequestHeaders, "Authorization, Mcp-Session-Id")
        }
        assertEquals(HttpStatusCode.OK, r.status)
        assertEquals("http://localhost:5173", r.headers[HttpHeaders.AccessControlAllowOrigin])
        assertTrue(r.headers[HttpHeaders.AccessControlAllowHeaders]!!.contains("Mcp-Session-Id", ignoreCase = true))
        // Without an Origin, OPTIONS is an ordinary request and still needs the token.
        assertEquals(HttpStatusCode.Unauthorized, c.options("/mcp") { header(HttpHeaders.Host, "localhost") }.status)
    }

    /**
     * Pins what a preflight may advertise, as a property rather than an exact string.
     *
     * Ktor 3.6.0 (KTOR-2912) began adding the CORS-safelisted methods GET/POST/HEAD to
     * Access-Control-Allow-Methods by default. That is benign here — browsers never preflight those —
     * but it showed that a dependency bump can change this header with no test noticing. This fails
     * if any future version advertises a method the transport does not serve, and it checks the half
     * that matters most: an origin that is NOT allow-listed gets no CORS grant at all.
     */
    @Test
    fun `cors advertises only the methods the transport serves, and nothing to unlisted origins`() =
        app(loopbackToken.copy(allowedOrigins = listOf("http://localhost:5173"))) { c ->
            val allowed = c.options("/mcp") {
                header(HttpHeaders.Host, "localhost:3072")
                header(HttpHeaders.Origin, "http://localhost:5173")
                header(HttpHeaders.AccessControlRequestMethod, "DELETE")
            }
            val methods = allowed.headers[HttpHeaders.AccessControlAllowMethods].orEmpty()
                .split(',').map { it.trim().uppercase() }.filter { it.isNotEmpty() }.toSet()
            assertTrue("DELETE" in methods, "session teardown must stay reachable: $methods")
            val served = setOf("GET", "POST", "DELETE", "OPTIONS", "HEAD")
            assertTrue(methods.all { it in served }, "preflight advertised methods the transport does not serve: ${methods - served}")
            for (verb in listOf("PUT", "PATCH", "TRACE", "CONNECT")) assertFalse(verb in methods, "$verb must never be advertised")
            assertNull(allowed.headers[HttpHeaders.AccessControlAllowCredentials], "credentialed CORS is never granted")

            val unlisted = c.options("/mcp") {
                header(HttpHeaders.Host, "localhost:3072")
                header(HttpHeaders.Origin, "https://evil.example")
                header(HttpHeaders.AccessControlRequestMethod, "POST")
            }
            assertNull(unlisted.headers[HttpHeaders.AccessControlAllowOrigin], "an unlisted origin must get no CORS grant")
            assertNull(unlisted.headers[HttpHeaders.AccessControlAllowMethods])
        }

    @Test
    fun `bearer token is required and compared exactly`() = app(loopbackToken) { c ->
        val missing = c.get("/mcp") { header(HttpHeaders.Host, "localhost") }
        assertEquals(HttpStatusCode.Unauthorized, missing.status)
        assertTrue(missing.headers[HttpHeaders.WWWAuthenticate]!!.startsWith("Bearer"))
        assertEquals(HttpStatusCode.Unauthorized, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer wrong") }.status)
        assertEquals(HttpStatusCode.Unauthorized, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer s3cret-token-longer") }.status)
        assertEquals(HttpStatusCode.Unauthorized, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Basic czNjcmV0LXRva2Vu") }.status)
        assertEquals(HttpStatusCode.Unauthorized, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer") }.status)
        assertEquals(HttpStatusCode.OK, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "bearer s3cret-token") }.status)
        assertEquals(HttpStatusCode.OK, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer   s3cret-token") }.status)
    }

    @Test
    fun `repeated bad tokens are throttled per client`() = app(loopbackToken.copy(maxAuthFailures = 3)) { c ->
        repeat(3) {
            assertEquals(HttpStatusCode.Unauthorized, c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer nope") }.status)
        }
        // Even the correct token is refused once the budget is spent — the limiter runs before the compare.
        val blocked = c.get("/mcp") { header(HttpHeaders.Host, "localhost"); header(HttpHeaders.Authorization, "Bearer s3cret-token") }
        assertEquals(HttpStatusCode.TooManyRequests, blocked.status)
        assertEquals("60", blocked.headers[HttpHeaders.RetryAfter])
    }

    @Test
    fun `auth failure limiter windows, resets on success and bounds memory`() {
        var now = 1_000L
        val l = AuthFailureLimiter(maxFailures = 2, windowMillis = 100, clock = { now }, maxTrackedClients = 2)
        assertFalse(l.isBlocked("a"))
        l.recordFailure("a"); assertFalse(l.isBlocked("a"))
        l.recordFailure("a"); assertTrue(l.isBlocked("a"))
        now += 100
        assertFalse(l.isBlocked("a")) // window expired
        l.recordFailure("a"); l.recordFailure("a"); assertTrue(l.isBlocked("a"))
        l.recordSuccess("a"); assertFalse(l.isBlocked("a"))
        // Capacity: the oldest tracked client is evicted when a new one arrives.
        l.recordFailure("a"); l.recordFailure("a"); l.recordFailure("b"); l.recordFailure("b"); l.recordFailure("c")
        assertFalse(l.isBlocked("a"))
        assertTrue(l.isBlocked("b"))
        // A stale entry is replaced rather than incremented.
        now += 100
        l.recordFailure("b"); assertFalse(l.isBlocked("b"))
    }

    @Test
    fun `oversized declared bodies are refused`() = app(loopbackNoToken.copy(maxBodyBytes = 10)) { c ->
        val r = c.post("/mcp") {
            header(HttpHeaders.Host, "localhost")
            contentType(ContentType.Application.Json)
            setBody("{\"a\":\"0123456789abcdef\"}")
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, r.status)
        val small = c.post("/mcp") { header(HttpHeaders.Host, "localhost"); contentType(ContentType.Application.Json); setBody("{}") }
        assertEquals(HttpStatusCode.OK, small.status)
        assertTrue(c.delete("/mcp") { header(HttpHeaders.Host, "localhost") }.status.value in setOf(404, 405))
    }

    @Test
    fun `origin normalisation`() {
        assertEquals("https://app.example", normalizeOrigin("HTTPS://App.Example:443/"))
        assertEquals("http://app.example", normalizeOrigin("http://app.example:80"))
        assertEquals("http://app.example:8080", normalizeOrigin("http://app.example:8080"))
        assertNull(normalizeOrigin("*"))
        assertNull(normalizeOrigin("null"))
        assertNull(normalizeOrigin(""))
        assertNull(normalizeOrigin("app.example"))
        assertNull(normalizeOrigin("https://app.example/path"))
        assertNull(normalizeOrigin("https://user@app.example"))
        assertNull(normalizeOrigin("https://app.example?x"))
        assertNull(normalizeOrigin("https://"))
    }

    @Test
    fun `helpers`() {
        assertEquals("localhost", hostPart("localhost:3072"))
        assertEquals("[::1]", hostPart("[::1]:3072"))
        assertEquals("abc", bearerToken("Bearer abc"))
        assertNull(bearerToken("Token abc"))
        assertNull(bearerToken("Bearer"))
        assertNull(bearerToken("Bearer "))
        assertTrue(constantTimeEquals("a", "a"))
        assertFalse(constantTimeEquals("a", "b"))
        assertFalse(constantTimeEquals("a", "ab"))
        assertTrue(isLoopback("127.0.0.1"))
        assertTrue(isLoopback("127.5.5.5"))
        assertTrue(isLoopback("localhost"))
        assertTrue(isLoopback("LOCALHOST"))
        assertTrue(isLoopback("::1"))
        assertTrue(isLoopback("[::1]"))
        assertFalse(isLoopback("0.0.0.0"))
        assertFalse(isLoopback("10.0.0.5"))
        assertFalse(isLoopback("::"))
    }
}
