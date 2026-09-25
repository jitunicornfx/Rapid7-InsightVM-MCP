package com.jitunicornfx.insightvm.mcp

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import java.net.InetAddress
import java.security.MessageDigest

/** Settings for the `--http` transport's request guard. */
data class HttpSecurity(
    /** Interface the server binds to; used for the `Host` header check and the token requirement. */
    val bindHost: String,
    val bindPort: Int,
    /** Shared secret expected as `Authorization: Bearer <token>`; null disables the check (loopback only). */
    val token: String?,
    /** Browser origins (`scheme://host[:port]`) allowed to make cross-origin requests. */
    val allowedOrigins: List<String>,
    /** Requests larger than this (by `Content-Length`) are refused with 413. */
    val maxBodyBytes: Long = DEFAULT_MAX_BODY_BYTES,
    /** Failed bearer attempts allowed per client address per [authFailureWindowMillis] before 429s. */
    val maxAuthFailures: Int = DEFAULT_MAX_AUTH_FAILURES,
    val authFailureWindowMillis: Long = DEFAULT_AUTH_FAILURE_WINDOW_MILLIS,
) {
    /** Written out by hand: the generated one would print [token], and settings objects end up in logs. */
    override fun toString(): String =
        "HttpSecurity(bindHost=$bindHost, bindPort=$bindPort, token=${if (token == null) "unset" else "***"}, " +
            "allowedOrigins=$allowedOrigins, maxBodyBytes=$maxBodyBytes, maxAuthFailures=$maxAuthFailures, " +
            "authFailureWindowMillis=$authFailureWindowMillis)"

    companion object {
        const val DEFAULT_MAX_BODY_BYTES = 4L * 1024 * 1024
        const val DEFAULT_MAX_AUTH_FAILURES = 20
        const val DEFAULT_AUTH_FAILURE_WINDOW_MILLIS = 60_000L

        /**
         * Shortest bearer token accepted on a non-loopback bind (and warned about on loopback). The
         * failure throttle is per client address, so an attacker spreading guesses across addresses is
         * held back only by the token's own entropy; 32 characters is 128 bits as hex, and
         * `openssl rand -hex 32` produces twice that.
         */
        const val MIN_TOKEN_LENGTH = 32
    }
}

/**
 * Sliding-window counter of failed authentication attempts per client address, so a weak bearer
 * token cannot be brute-forced at line rate. Memory is bounded: entries expire with the window and
 * the table is capped, evicting the oldest entry when full.
 */
internal class AuthFailureLimiter(
    private val maxFailures: Int,
    private val windowMillis: Long,
    private val clock: () -> Long = System::currentTimeMillis,
    private val maxTrackedClients: Int = 10_000,
) {
    private class Entry(var windowStart: Long, var failures: Int)

    private val entries = LinkedHashMap<String, Entry>()

    /** True when [client] has exhausted its budget and must be refused before credentials are even checked. */
    @Synchronized
    fun isBlocked(client: String): Boolean {
        val now = clock()
        val e = entries[client] ?: return false
        if (now - e.windowStart >= windowMillis) {
            entries.remove(client)
            return false
        }
        return e.failures >= maxFailures
    }

    @Synchronized
    fun recordFailure(client: String) {
        val now = clock()
        val e = entries[client]
        if (e == null || now - e.windowStart >= windowMillis) {
            if (e == null && entries.size >= maxTrackedClients) {
                entries.remove(entries.keys.first())
            }
            entries[client] = Entry(now, 1)
        } else {
            e.failures++
        }
    }

    @Synchronized
    fun recordSuccess(client: String) {
        entries.remove(client)
    }
}

/**
 * Hardening for the Streamable-HTTP/SSE transport. Installed before the MCP routes so every request
 * passes through it first:
 *
 *  1. **Host check** (loopback binds) — the `Host` header must name this server (bind address,
 *     `localhost`, a loopback address, or an allow-listed origin's host). Defeats DNS rebinding, where
 *     a malicious page resolves its own name to 127.0.0.1 and talks to the local server with a
 *     foreign `Host`.
 *  2. **Origin check** — browsers always send `Origin` on cross-origin requests; unless the origin is
 *     allow-listed the request is refused with 403. Non-browser MCP clients send no `Origin`.
 *  3. **Bearer token** — when configured, every request must carry the exact token; comparison is
 *     constant-time. Startup refuses to bind a non-loopback interface without a token of at least
 *     [HttpSecurity.MIN_TOKEN_LENGTH] characters.
 *  4. **Body size cap** — declared `Content-Length` above the limit is refused with 413.
 *  5. **Brute-force throttle** — after [HttpSecurity.maxAuthFailures] bad tokens from one client
 *     address within the window, further attempts get 429 until the window passes.
 *  6. **CORS** — default-deny; only the allow-listed origins get CORS headers.
 */
fun Application.installTransportSecurity(security: HttpSecurity) {
    val allowedOriginSet = security.allowedOrigins.mapNotNull { normalizeOrigin(it) }.toSet()
    val allowedHosts = buildSet {
        add(security.bindHost.lowercase())
        add("localhost")
        add("127.0.0.1")
        add("[::1]")
        add("::1")
        allowedOriginSet.forEach { origin -> add(origin.substringAfter("://").substringBefore(':')) }
    }

    val enforceHost = isLoopback(security.bindHost)
    val limiter = AuthFailureLimiter(security.maxAuthFailures, security.authFailureWindowMillis)

    intercept(ApplicationCallPipeline.Plugins) {
        val request = call.request

        // DNS rebinding only matters for a loopback bind (the attack reaches a local server through the
        // victim's browser). On other interfaces the bearer token is mandatory and clients legitimately
        // use arbitrary host names, so the Host check is skipped there.
        val host = request.header(HttpHeaders.Host)?.trim()?.lowercase()
        if (enforceHost && (host == null || hostPart(host) !in allowedHosts)) {
            call.respondText("Host header not accepted by this server.", status = HttpStatusCode(421, "Misdirected Request"))
            return@intercept finish()
        }

        request.header(HttpHeaders.Origin)?.let { origin ->
            val normalized = normalizeOrigin(origin)
            if (normalized == null || normalized !in allowedOriginSet) {
                call.respondText("Origin not allowed.", status = HttpStatusCode.Forbidden)
                return@intercept finish()
            }
        }

        // CORS preflights carry no credentials; let the CORS plugin answer them (only for allowed origins).
        val isPreflight = request.httpMethod == HttpMethod.Options && request.header(HttpHeaders.Origin) != null

        security.token?.let { expected ->
            if (!isPreflight) {
                val client = request.origin.remoteAddress
                if (limiter.isBlocked(client)) {
                    call.response.header(HttpHeaders.RetryAfter, (security.authFailureWindowMillis / 1000).toString())
                    call.respondText("Too many failed authentication attempts.", status = HttpStatusCode.TooManyRequests)
                    return@intercept finish()
                }
                val presented = request.header(HttpHeaders.Authorization)?.let(::bearerToken)
                if (presented == null || !constantTimeEquals(presented, expected)) {
                    limiter.recordFailure(client)
                    call.response.header(HttpHeaders.WWWAuthenticate, "Bearer realm=\"$SERVER_NAME\"")
                    call.respondText("Unauthorized.", status = HttpStatusCode.Unauthorized)
                    return@intercept finish()
                }
                limiter.recordSuccess(client)
            }
        }

        request.header(HttpHeaders.ContentLength)?.toLongOrNull()?.let { length ->
            if (length > security.maxBodyBytes) {
                call.respondText("Request body too large.", status = HttpStatusCode.PayloadTooLarge)
                return@intercept finish()
            }
        }
    }

    install(CORS) {
        // No anyHost(): the server fronts credentialed APIs, so only explicitly allow-listed browser
        // origins may call it. Non-browser MCP clients are unaffected.
        allowedOriginSet.forEach { origin ->
            val scheme = origin.substringBefore("://")
            val hostAndPort = origin.substringAfter("://")
            allowHost(hostAndPort, schemes = listOf(scheme))
        }
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Options)
        allowHeader(HttpHeaders.Authorization)
        allowHeader("Mcp-Session-Id")
        allowHeader("MCP-Protocol-Version")
        allowHeader("Last-Event-ID")
        exposeHeader("Mcp-Session-Id")
        allowNonSimpleContentTypes = true
    }
}

/** `scheme://host[:port]` lowercased with default ports stripped, or null if unparseable / wildcard. */
internal fun normalizeOrigin(origin: String): String? {
    val trimmed = origin.trim().lowercase().trimEnd('/')
    if (trimmed.isEmpty() || trimmed == "*" || trimmed == "null") return null
    val scheme = trimmed.substringBefore("://", missingDelimiterValue = "")
    if (scheme != "http" && scheme != "https") return null
    val rest = trimmed.substringAfter("://")
    if (rest.isEmpty() || rest.contains('/') || rest.contains('@') || rest.contains('?') || rest.contains('#')) return null
    val defaultPort = if (scheme == "https") ":443" else ":80"
    val hostPort = if (rest.endsWith(defaultPort)) rest.removeSuffix(defaultPort) else rest
    return "$scheme://$hostPort"
}

/** Strip the port from a `Host` header value, keeping IPv6 brackets intact. */
internal fun hostPart(host: String): String =
    if (host.startsWith("[")) host.substringBefore("]") + "]" else host.substringBefore(':')

internal fun bearerToken(header: String): String? {
    val parts = header.trim().split(Regex("\\s+"), limit = 2)
    if (parts.size != 2 || !parts[0].equals("Bearer", ignoreCase = true)) return null
    return parts[1].takeIf { it.isNotEmpty() }
}

internal fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

/** True for `localhost` and loopback addresses (`127.0.0.0/8`, `::1`). */
internal fun isLoopback(host: String): Boolean {
    val h = host.trim().trimStart('[').trimEnd(']').lowercase()
    if (h == "localhost") return true
    return runCatching { InetAddress.getByName(h).isLoopbackAddress }.getOrDefault(false)
}
