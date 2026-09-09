package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import kotlinx.serialization.json.JsonElement
import okhttp3.OkHttpClient
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * HTTP wrapper around the two InsightVM API families.
 *
 *  - Security Console (v3): HTTP Basic authentication, optional `Token` 2FA header, operator-chosen
 *    TLS trust ([TlsSupport]).
 *  - Cloud Integrations (v4): `X-Api-Key` against the regional Insight Platform host.
 *
 * Responses are never thrown on non-2xx; bodies are read through a size cap so a hostile or
 * runaway response cannot exhaust memory; redirects are never followed (a 3xx could otherwise
 * bounce credentials to an arbitrary `Location`).
 */
class Rapid7Client(
    private val config: Config,
    consoleEngine: HttpClientEngine? = null,
    cloudEngine: HttpClientEngine? = null,
    private val warn: (String) -> Unit = { System.err.println(it) },
) : AutoCloseable {

    /** Raw HTTP result. Exactly one of [text] / [bytes] is set for non-empty bodies. */
    data class ApiResponse(
        val status: Int,
        val ok: Boolean,
        val contentType: String?,
        val text: String? = null,
        val bytes: ByteArray? = null,
        val truncated: Boolean = false,
        val limitBytes: Long = 0,
    )

    private val consoleHttp: HttpClient? = config.console?.let { console ->
        if (consoleEngine != null) {
            HttpClient(consoleEngine) { configureClient() }
        } else {
            // Build the OkHttp client eagerly (engine { config { } } runs lazily on first use) so TLS
            // misconfiguration fails — and the insecure-mode banner prints — at startup.
            val okHttp = OkHttpClient.Builder().also { TlsSupport.apply(it, console, warn) }.build()
            HttpClient(OkHttp) {
                engine { preconfigured = okHttp }
                configureClient()
            }
        }
    }

    private val cloudHttp: HttpClient? = config.cloud?.let {
        if (cloudEngine != null) HttpClient(cloudEngine) { configureClient() } else HttpClient(OkHttp) { configureClient() }
    }

    private fun HttpClientConfig<*>.configureClient() {
        expectSuccess = false
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = config.requestTimeoutMillis
            connectTimeoutMillis = 15_000
            socketTimeoutMillis = config.requestTimeoutMillis
        }
    }

    private val basicAuthHeader: String? = config.console?.let {
        "Basic " + Base64.getEncoder().encodeToString("${it.username}:${it.password}".toByteArray(Charsets.UTF_8))
    }

    fun baseUrlFor(family: ApiFamily): String = when (family) {
        ApiFamily.CONSOLE -> config.console?.baseUrl
        ApiFamily.CLOUD -> config.cloud?.baseUrl
    } ?: throw IllegalStateException("${family.displayName} is not configured.")

    private fun httpFor(family: ApiFamily): HttpClient = when (family) {
        ApiFamily.CONSOLE -> consoleHttp
        ApiFamily.CLOUD -> cloudHttp
    } ?: throw IllegalStateException("${family.displayName} is not configured.")

    /** Normalize a URL to a `scheme://host:port` origin (lowercased), or null if it can't be parsed. */
    private fun originOf(url: String): String? =
        runCatching { Url(url) }.getOrNull()?.takeIf { it.host.isNotEmpty() }?.let {
            "${it.protocol.name}://${it.host.lowercase()}:${it.port}"
        }

    /**
     * Whether an API-provided URL (a HATEOAS `links[].href` or a paging cursor link) may be
     * requested with credentials attached. Validation is on the parsed origin — never a string
     * prefix — and the origin must exactly equal the configured base for that [family].
     */
    internal fun isAllowedFollowUrl(family: ApiFamily, url: String): Boolean {
        val base = when (family) {
            ApiFamily.CONSOLE -> config.console?.baseUrl
            ApiFamily.CLOUD -> config.cloud?.baseUrl
        } ?: return false
        if (url.contains('@')) return false
        val origin = originOf(url) ?: return false
        return origin == originOf(base)
    }

    /**
     * Perform a request against [family].
     *
     * @param path path beginning with `/`, already percent-encoded (see [seg]).
     * @param query query parameters; repeated keys are sent as repeated parameters.
     * @param jsonBody optional JSON body (takes precedence over [rawBody]).
     * @param rawBody optional raw string body sent with [rawContentType].
     * @param accept value of the `Accept` header; defaults to JSON.
     */
    suspend fun request(
        family: ApiFamily,
        method: HttpMethod,
        path: String,
        query: Map<String, List<String>> = emptyMap(),
        jsonBody: JsonElement? = null,
        rawBody: String? = null,
        rawContentType: ContentType = ContentType.Text.Plain,
        accept: ContentType = ContentType.Application.Json,
    ): ApiResponse {
        require(path.startsWith("/")) { "path must start with '/'" }
        val response = httpFor(family).request(baseUrlFor(family) + path) {
            this.method = method
            applyAuth(family)
            header(HttpHeaders.Accept, accept.toString())
            url {
                query.forEach { (key, values) -> values.forEach { value -> parameters.append(key, value) } }
            }
            when {
                jsonBody != null -> {
                    contentType(ContentType.Application.Json)
                    setBody(JsonCodec.compact.encodeToString(JsonElement.serializer(), jsonBody))
                }
                rawBody != null -> {
                    contentType(rawContentType)
                    setBody(rawBody)
                }
            }
        }
        return response.toApiResponse()
    }

    /** GET an absolute URL returned by the API itself, refused unless it targets the configured origin. */
    suspend fun requestAbsolute(family: ApiFamily, url: String, accept: ContentType = ContentType.Application.Json): ApiResponse {
        require(isAllowedFollowUrl(family, url)) { "Refusing to follow a URL outside the configured ${family.displayName} origin." }
        val response = httpFor(family).request(url) {
            method = HttpMethod.Get
            applyAuth(family)
            header(HttpHeaders.Accept, accept.toString())
        }
        return response.toApiResponse()
    }

    private fun io.ktor.client.request.HttpRequestBuilder.applyAuth(family: ApiFamily) {
        when (family) {
            ApiFamily.CONSOLE -> {
                header(HttpHeaders.Authorization, basicAuthHeader)
                config.console?.twoFactorToken?.let { header("Token", it) }
            }
            ApiFamily.CLOUD -> header("X-Api-Key", config.cloud?.apiKey)
        }
    }

    private suspend fun HttpResponse.toApiResponse(): ApiResponse {
        val limit = config.maxResponseBytes
        val (read, truncated) = readCapped(bodyAsChannel(), limit)
        val ct = contentType()
        // Only a capped body can end mid-character; an untruncated one is well-formed by construction.
        val bytes = if (truncated && charsetOf(ct) == Charsets.UTF_8) trimIncompleteUtf8(read) else read
        val ctString = ct?.toString()
        val textual = ct == null || isTextual(ct)
        return ApiResponse(
            status = status.value,
            ok = status.value in 200..299,
            contentType = ctString,
            text = if (textual) bytes.toString(charsetOf(ct)) else null,
            bytes = if (textual) null else bytes,
            truncated = truncated,
            limitBytes = limit,
        )
    }

    private fun charsetOf(ct: ContentType?): java.nio.charset.Charset =
        ct?.parameter("charset")?.let { runCatching { charset(it) }.getOrNull() } ?: Charsets.UTF_8

    override fun close() {
        consoleHttp?.close()
        cloudHttp?.close()
    }

    companion object {
        internal fun isTextual(ct: ContentType): Boolean {
            val type = ct.contentType.lowercase()
            val sub = ct.contentSubtype.lowercase()
            return type == "text" || sub.contains("json") || sub.contains("xml") || sub.contains("javascript") ||
                sub == "x-www-form-urlencoded"
        }

        /**
         * Drop a trailing incomplete UTF-8 sequence, so decoding a body that the cap split
         * mid-character cannot produce a U+FFFD replacement (and cannot corrupt the final record of
         * an exported file). Scans back at most three bytes; a well-formed body is returned as-is.
         */
        internal fun trimIncompleteUtf8(bytes: ByteArray): ByteArray {
            if (bytes.isEmpty()) return bytes
            // Walk back over continuation bytes (10xxxxxx) to the sequence's lead byte.
            var lead = bytes.size - 1
            while (lead >= 0 && (bytes[lead].toInt() and 0xC0) == 0x80) {
                if (bytes.size - lead > 4) return bytes // more continuations than any sequence allows
                lead--
            }
            if (lead < 0) return bytes
            val b = bytes[lead].toInt() and 0xFF
            val expected = when {
                b and 0x80 == 0x00 -> 1
                b and 0xE0 == 0xC0 -> 2
                b and 0xF0 == 0xE0 -> 3
                b and 0xF8 == 0xF0 -> 4
                else -> return bytes // not a valid lead byte; leave it alone
            }
            return if (lead + expected > bytes.size) bytes.copyOf(lead) else bytes
        }

        /** Read at most [limit] bytes from [channel]; returns the bytes and whether more remained. */
        internal suspend fun readCapped(channel: ByteReadChannel, limit: Long): Pair<ByteArray, Boolean> {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16 * 1024)
            var truncated = false
            while (true) {
                val read = channel.readAvailable(buffer, 0, buffer.size)
                if (read < 0) break
                if (read == 0) continue
                // Long arithmetic: `limit` comes from configuration and can exceed Int.MAX_VALUE,
                // where narrowing the remaining room would wrap negative and throw on write().
                val remaining: Long = limit - out.size()
                if (read > remaining) {
                    // Safe narrowing: remaining < read <= buffer.size.
                    out.write(buffer, 0, remaining.toInt())
                    truncated = true
                    channel.cancel(null)
                    break
                }
                out.write(buffer, 0, read)
                if (out.size() >= limit) {
                    // Exactly at the cap: the body is only truncated if at least one more byte follows.
                    truncated = channel.readAvailable(buffer, 0, 1) > 0
                    channel.cancel(null)
                    break
                }
            }
            return out.toByteArray() to truncated
        }
    }
}
