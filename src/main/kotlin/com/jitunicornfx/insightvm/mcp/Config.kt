package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import io.ktor.http.URLProtocol
import io.ktor.http.Url

/**
 * Insight Platform regional data centers for the Cloud Integrations API
 * (`https://{region}.api.insight.rapid7.com/vm/`).
 */
enum class Region(val code: String) {
    US("us"),
    US2("us2"),
    US3("us3"),
    EU("eu"),
    CA("ca"),
    AU("au"),
    AP("ap"),
    APS2("aps2"),
    ME1("me1");

    companion object {
        fun fromCode(value: String): Region {
            val normalized = value.trim().lowercase()
            return entries.firstOrNull { it.code == normalized }
                ?: throw IllegalArgumentException(
                    "Unknown InsightVM region '$value'. Valid regions: " + entries.joinToString(", ") { it.code },
                )
        }
    }
}

/** Connection settings for an on-premises Security Console (API v3, HTTP Basic authentication). */
data class ConsoleConfig(
    /** Origin of the console, e.g. `https://console.example.internal:3780` (no path). */
    val baseUrl: String,
    val username: String,
    val password: String,
    /** Two-factor authentication token sent in the `Token` header, when the account requires it. */
    val twoFactorToken: String? = null,
    /** Path to a PEM file holding the CA (or self-signed leaf) certificate(s) to trust for the console. */
    val caCertPath: String? = null,
    /** Disable TLS certificate and hostname verification. Dangerous; logged loudly. */
    val insecureTls: Boolean = false,
) {
    override fun toString(): String =
        "ConsoleConfig(baseUrl=$baseUrl, username=$username, password=***, " +
            "twoFactorToken=${if (twoFactorToken == null) "unset" else "***"}, caCertPath=$caCertPath, insecureTls=$insecureTls)"
}

/** Connection settings for the Insight Platform Cloud Integrations API (v4, `X-Api-Key`). */
data class CloudConfig(
    val apiKey: String,
    val region: Region,
    /** Base URL including the `/vm` prefix; operation paths (`/v4/integration/...`) are appended. */
    val baseUrl: String = "https://${region.code}.api.insight.rapid7.com/vm",
) {
    override fun toString(): String = "CloudConfig(region=${region.code}, baseUrl=$baseUrl, apiKey=***)"
}

/** Which catalog operations get registered as tools. */
data class ToolFilter(
    /** Only register `GET` operations. */
    val readOnly: Boolean = false,
    /** Keep only operations whose tag (case-insensitive) is in this set; empty = all. */
    val tags: Set<String> = emptySet(),
    /** Drop operations whose tag is in this set. */
    val excludeTags: Set<String> = emptySet(),
    /** Register the console command-execution operation (off by default). */
    val allowAdminCommands: Boolean = false,
    /** API families to expose; intersected with what is configured. */
    val families: Set<ApiFamily> = ApiFamily.entries.toSet(),
    /** Glob patterns (`*`, `?`) on tool names; empty = all. */
    val nameGlobs: List<String> = emptyList(),
) {
    companion object {
        /** Tag value that matches nothing; used when two tag allow-lists have no overlap. */
        const val NO_TAGS_SENTINEL = "<<none>>"
    }

    /** Combine with another filter so the result is at least as restrictive as both. */
    fun tighten(other: ToolFilter): ToolFilter = ToolFilter(
        readOnly = readOnly || other.readOnly,
        tags = when {
            tags.isEmpty() -> other.tags
            other.tags.isEmpty() -> tags
            else -> tags.map { it.lowercase() }.toSet().intersect(other.tags.map { it.lowercase() }.toSet())
                .ifEmpty { setOf(NO_TAGS_SENTINEL) }
        },
        excludeTags = excludeTags + other.excludeTags,
        allowAdminCommands = allowAdminCommands && other.allowAdminCommands,
        families = families.intersect(other.families),
        nameGlobs = nameGlobs + other.nameGlobs,
    )
}

/**
 * Runtime configuration, resolved from environment variables by [fromEnv]. At least one of
 * [console] / [cloud] must be configured.
 */
data class Config(
    val console: ConsoleConfig?,
    val cloud: CloudConfig?,
    val requestTimeoutMillis: Long = DEFAULT_TIMEOUT_MS,
    /** Upper bound on bytes read from any API response body; larger bodies are truncated. */
    val maxResponseBytes: Long = DEFAULT_MAX_RESPONSE_BYTES,
    /** Shared secret required as `Authorization: Bearer` on the `--http` transport. */
    val httpAuthToken: String? = null,
    /** Browser origins permitted in `--http` mode (CORS + Origin check). Empty = deny all browsers. */
    val httpAllowedOrigins: List<String> = emptyList(),
    val filter: ToolFilter = ToolFilter(),
    val updateCheckDisabled: Boolean = false,
    val autoUpdateDisabled: Boolean = false,
) {
    init {
        require(console != null || cloud != null) {
            "Nothing to serve: configure the Security Console ($ENV_CONSOLE_URL, $ENV_CONSOLE_USERNAME, " +
                "$ENV_CONSOLE_PASSWORD) and/or the Cloud API ($ENV_API_KEY, $ENV_REGION)."
        }
    }

    /** Families that are both configured and not filtered out. */
    val activeFamilies: Set<ApiFamily>
        get() = buildSet {
            if (console != null && ApiFamily.CONSOLE in filter.families) add(ApiFamily.CONSOLE)
            if (cloud != null && ApiFamily.CLOUD in filter.families) add(ApiFamily.CLOUD)
        }

    override fun toString(): String =
        "Config(console=$console, cloud=$cloud, requestTimeoutMillis=$requestTimeoutMillis, " +
            "maxResponseBytes=$maxResponseBytes, httpAuthToken=${if (httpAuthToken == null) "unset" else "***"}, " +
            "httpAllowedOrigins=$httpAllowedOrigins, filter=$filter)"

    companion object {
        const val ENV_CONSOLE_URL = "INSIGHTVM_CONSOLE_URL"
        const val ENV_CONSOLE_USERNAME = "INSIGHTVM_CONSOLE_USERNAME"
        const val ENV_CONSOLE_PASSWORD = "INSIGHTVM_CONSOLE_PASSWORD"
        const val ENV_CONSOLE_2FA_TOKEN = "INSIGHTVM_CONSOLE_2FA_TOKEN"
        const val ENV_CONSOLE_CA_CERT = "INSIGHTVM_CONSOLE_CA_CERT"
        const val ENV_CONSOLE_INSECURE_TLS = "INSIGHTVM_CONSOLE_INSECURE_TLS"
        const val ENV_ALLOW_HTTP = "INSIGHTVM_ALLOW_HTTP"
        const val ENV_API_KEY = "INSIGHTVM_API_KEY"
        const val ENV_REGION = "INSIGHTVM_REGION"
        const val ENV_CLOUD_BASE_URL = "INSIGHTVM_CLOUD_BASE_URL"
        const val ENV_TIMEOUT_MS = "INSIGHTVM_TIMEOUT_MS"
        const val ENV_MAX_RESPONSE_BYTES = "INSIGHTVM_MAX_RESPONSE_BYTES"
        const val ENV_MCP_AUTH_TOKEN = "INSIGHTVM_MCP_AUTH_TOKEN"
        const val ENV_HTTP_ALLOWED_ORIGINS = "INSIGHTVM_HTTP_ALLOWED_ORIGINS"
        const val ENV_READ_ONLY = "INSIGHTVM_READ_ONLY"
        const val ENV_TAGS = "INSIGHTVM_TAGS"
        const val ENV_EXCLUDE_TAGS = "INSIGHTVM_EXCLUDE_TAGS"
        const val ENV_ALLOW_ADMIN_COMMANDS = "INSIGHTVM_ALLOW_ADMIN_COMMANDS"
        const val ENV_DISABLE_UPDATE_CHECK = "INSIGHTVM_DISABLE_UPDATE_CHECK"
        const val ENV_DISABLE_AUTO_UPDATE = "INSIGHTVM_DISABLE_AUTO_UPDATE"

        const val DEFAULT_REGION = "us"
        const val DEFAULT_TIMEOUT_MS = 60_000L
        const val DEFAULT_MAX_RESPONSE_BYTES = 5_000_000L
        const val DEFAULT_CONSOLE_PORT = 3780

        private val TRUTHY = setOf("1", "true", "yes", "on")
        private val HOST_PRESENT = Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/:?#@\\s]+")

        internal fun isTruthy(value: String?): Boolean = value?.trim()?.lowercase() in TRUTHY

        internal fun csv(value: String?): List<String> =
            value?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

        fun fromEnv(env: Map<String, String> = System.getenv()): Config {
            fun get(name: String): String? = env[name]?.takeIf { it.isNotBlank() }

            val console = consoleFromEnv(env)
            val cloud = get(ENV_API_KEY)?.let { key ->
                val region = Region.fromCode(get(ENV_REGION) ?: DEFAULT_REGION)
                val base = get(ENV_CLOUD_BASE_URL)?.trimEnd('/') ?: "https://${region.code}.api.insight.rapid7.com/vm"
                // The API key travels on every request; never let an override downgrade it to cleartext by accident.
                require(base.startsWith("https://") || (isTruthy(env[ENV_ALLOW_HTTP]) && base.startsWith("http://"))) {
                    "$ENV_CLOUD_BASE_URL must use https (set $ENV_ALLOW_HTTP=1 to permit cleartext http)."
                }
                CloudConfig(apiKey = key, region = region, baseUrl = base)
            }
            if (cloud == null && get(ENV_REGION) != null && console == null) {
                throw IllegalStateException("$ENV_REGION is set but $ENV_API_KEY is missing.")
            }

            val timeout = get(ENV_TIMEOUT_MS)?.toLongOrNull()?.takeIf { it > 0 } ?: DEFAULT_TIMEOUT_MS
            val maxBytes = get(ENV_MAX_RESPONSE_BYTES)?.toLongOrNull()?.takeIf { it > 0 } ?: DEFAULT_MAX_RESPONSE_BYTES
            val origins = csv(env[ENV_HTTP_ALLOWED_ORIGINS]).filter { it != "*" }

            val filter = ToolFilter(
                readOnly = isTruthy(env[ENV_READ_ONLY]),
                tags = csv(env[ENV_TAGS]).toSet(),
                excludeTags = csv(env[ENV_EXCLUDE_TAGS]).toSet(),
                allowAdminCommands = isTruthy(env[ENV_ALLOW_ADMIN_COMMANDS]),
            )

            return Config(
                console = console,
                cloud = cloud,
                requestTimeoutMillis = timeout,
                maxResponseBytes = maxBytes,
                httpAuthToken = get(ENV_MCP_AUTH_TOKEN),
                httpAllowedOrigins = origins,
                filter = filter,
                updateCheckDisabled = isTruthy(env[ENV_DISABLE_UPDATE_CHECK]),
                autoUpdateDisabled = isTruthy(env[ENV_DISABLE_AUTO_UPDATE]),
            )
        }

        private fun consoleFromEnv(env: Map<String, String>): ConsoleConfig? {
            fun get(name: String): String? = env[name]?.takeIf { it.isNotBlank() }
            val url = get(ENV_CONSOLE_URL)
            val user = get(ENV_CONSOLE_USERNAME)
            val password = get(ENV_CONSOLE_PASSWORD)
            if (url == null && user == null && password == null) return null
            if (url == null || user == null || password == null) {
                throw IllegalStateException(
                    "Incomplete Security Console configuration: $ENV_CONSOLE_URL, $ENV_CONSOLE_USERNAME and " +
                        "$ENV_CONSOLE_PASSWORD must all be set.",
                )
            }
            return ConsoleConfig(
                baseUrl = normalizeConsoleUrl(url, allowHttp = isTruthy(env[ENV_ALLOW_HTTP])),
                username = user,
                password = password,
                twoFactorToken = get(ENV_CONSOLE_2FA_TOKEN),
                caCertPath = get(ENV_CONSOLE_CA_CERT),
                insecureTls = isTruthy(env[ENV_CONSOLE_INSECURE_TLS]),
            )
        }

        /**
         * Validate and normalize the console URL to a bare origin. Only `https` is accepted unless
         * [allowHttp] is set (Basic credentials must not travel in cleartext by accident); a path,
         * query, fragment or userinfo component is rejected because the API paths are appended verbatim.
         */
        internal fun normalizeConsoleUrl(raw: String, allowHttp: Boolean = false): String {
            val trimmed = raw.trim()
            require(!trimmed.contains('@')) { "$ENV_CONSOLE_URL must not contain credentials; use $ENV_CONSOLE_USERNAME/$ENV_CONSOLE_PASSWORD." }
            // Ktor silently substitutes "localhost" for a missing host, so check the raw text first.
            require(HOST_PRESENT.containsMatchIn(trimmed)) { "$ENV_CONSOLE_URL has no host: $trimmed" }
            val parsed = runCatching { Url(trimmed) }.getOrElse { throw IllegalArgumentException("$ENV_CONSOLE_URL is not a valid URL: $trimmed") }
            require(parsed.host.isNotBlank()) { "$ENV_CONSOLE_URL has no host: $trimmed" }
            when (parsed.protocol) {
                URLProtocol.HTTPS -> Unit
                URLProtocol.HTTP -> require(allowHttp) {
                    "$ENV_CONSOLE_URL must use https (set $ENV_ALLOW_HTTP=1 to permit cleartext http)."
                }
                else -> throw IllegalArgumentException("$ENV_CONSOLE_URL must use https: $trimmed")
            }
            require(parsed.encodedPath.isEmpty() || parsed.encodedPath == "/") {
                "$ENV_CONSOLE_URL must be a bare origin without a path (got '${parsed.encodedPath}')."
            }
            require(parsed.encodedQuery.isEmpty() && parsed.encodedFragment.isEmpty()) {
                "$ENV_CONSOLE_URL must not contain a query string or fragment."
            }
            // A URL without an explicit port means the console's default (3780), not the scheme default.
            val port = if (parsed.specifiedPort == 0) DEFAULT_CONSOLE_PORT else parsed.specifiedPort
            return "${parsed.protocol.name}://${parsed.host.lowercase()}:$port"
        }
    }
}
