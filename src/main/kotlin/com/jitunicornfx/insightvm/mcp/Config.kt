package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.PagingDefaults
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
    /**
     * The account's two-factor code, sent in the `Token` header when the account requires it. It is
     * time-based, so a value fixed at startup soon stops working; see [Config.TWO_FACTOR_TOKEN_NOTE].
     */
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
    /**
     * Only register reads: every `GET`, plus the five POST searches in
     * [com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader.QUERY_ONLY_OPS]. The export tool is
     * also dropped, because it writes files. The secret gate ([allowSecretTools]) still applies to
     * the reads it keeps.
     */
    val readOnly: Boolean = false,
    /** Keep only operations whose tag (case-insensitive) is in this set; empty = all. */
    val tags: Set<String> = emptySet(),
    /** Drop operations whose tag is in this set. */
    val excludeTags: Set<String> = emptySet(),
    /** Register the console command-execution operation (off by default). */
    val allowAdminCommands: Boolean = false,
    /**
     * Register the operations that return or set authentication secrets (off by default, and
     * independent of [readOnly]: two of them are reads). See
     * [com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader.SENSITIVE_OPS].
     */
    val allowSecretTools: Boolean = false,
    /** API families to expose; intersected with what is configured. */
    val families: Set<ApiFamily> = ApiFamily.entries.toSet(),
    /** Glob patterns (`*`, `?`) on tool names, case-insensitive like [tags]; empty = all. */
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
        allowSecretTools = allowSecretTools && other.allowSecretTools,
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
    /**
     * Upper bound on bytes read from any API response body — a MEMORY guard, not a context budget.
     * It must stay comfortably above the largest complete response the API can return, because a
     * body cut mid-stream is unparseable and so cannot be trimmed intelligently. What reaches the
     * model is bounded by [maxResultChars] instead.
     */
    val maxResponseBytes: Long = DEFAULT_MAX_RESPONSE_BYTES,
    /** Ceiling on the rendered characters of API data in one tool result. See [ResultBudget]. */
    val maxResultChars: Int = DEFAULT_MAX_RESULT_CHARS,
    /** Keep the per-record HATEOAS `links` that are stripped by default. See [pruneRecordLinks]. */
    val keepRecordLinks: Boolean = false,
    /** `size` injected when a paged operation is called without one. See [PagingDefaults]. */
    val defaultPageSize: Int = PagingDefaults.DEFAULT_PAGE_SIZE,
    /** Where exported results are written; null means the per-user default. See [SpoolStore]. */
    val spoolDirectory: String? = null,
    /** Hours an exported file survives before the startup sweep removes it; 0 never sweeps. */
    val spoolRetentionHours: Int = DEFAULT_SPOOL_RETENTION_HOURS,
    /** Whether insightvm_export_to_file is registered at all — the only tool that writes files. */
    val exportDisabled: Boolean = false,
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
            "maxResponseBytes=$maxResponseBytes, maxResultChars=$maxResultChars, keepRecordLinks=$keepRecordLinks, defaultPageSize=$defaultPageSize, spoolDirectory=$spoolDirectory, exportDisabled=$exportDisabled, " +
            "httpAuthToken=${if (httpAuthToken == null) "unset" else "***"}, " +
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
        const val ENV_MAX_RESULT_CHARS = "INSIGHTVM_MAX_RESULT_CHARS"
        const val ENV_KEEP_RECORD_LINKS = "INSIGHTVM_KEEP_RECORD_LINKS"
        const val ENV_DEFAULT_PAGE_SIZE = "INSIGHTVM_DEFAULT_PAGE_SIZE"
        const val ENV_SPOOL_DIR = "INSIGHTVM_SPOOL_DIR"
        const val ENV_SPOOL_RETENTION_HOURS = "INSIGHTVM_SPOOL_RETENTION_HOURS"
        const val ENV_DISABLE_EXPORT = "INSIGHTVM_DISABLE_EXPORT"
        const val ENV_MCP_AUTH_TOKEN = "INSIGHTVM_MCP_AUTH_TOKEN"
        const val ENV_HTTP_ALLOWED_ORIGINS = "INSIGHTVM_HTTP_ALLOWED_ORIGINS"
        const val ENV_READ_ONLY = "INSIGHTVM_READ_ONLY"
        const val ENV_TAGS = "INSIGHTVM_TAGS"
        const val ENV_EXCLUDE_TAGS = "INSIGHTVM_EXCLUDE_TAGS"
        const val ENV_ALLOW_ADMIN_COMMANDS = "INSIGHTVM_ALLOW_ADMIN_COMMANDS"
        const val ENV_ALLOW_SECRET_TOOLS = "INSIGHTVM_ALLOW_SECRET_TOOLS"
        const val ENV_DISABLE_UPDATE_CHECK = "INSIGHTVM_DISABLE_UPDATE_CHECK"
        const val ENV_DISABLE_AUTO_UPDATE = "INSIGHTVM_DISABLE_AUTO_UPDATE"

        const val DEFAULT_REGION = "us"
        const val DEFAULT_TIMEOUT_MS = 60_000L
        const val DEFAULT_MAX_RESPONSE_BYTES = 16_777_216L

        /** An env typo must not be able to exhaust the heap. */
        const val MAX_RESPONSE_BYTES_CEILING = 268_435_456L

        const val DEFAULT_MAX_RESULT_CHARS = ResultBudget.DEFAULT_MAX_CHARS

        /** Below this a result is too small to be diagnostically useful; a misconfiguration clamps up. */
        const val MIN_MAX_RESULT_CHARS = 2_000

        /**
         * There is deliberately no "unlimited" value: one environment variable must not be able to
         * silently reinstate an unbounded result. Raise the number instead.
         */
        const val MAX_MAX_RESULT_CHARS = 5_000_000

        const val DEFAULT_SPOOL_RETENTION_HOURS = 24

        const val DEFAULT_CONSOLE_PORT = 3780

        /**
         * What the console's `Token` header actually is, for the startup warning and the 401 hint. The
         * console checks the header on every request and this client keeps no session, so a code that
         * was valid at startup is refused within about a minute; re-checking the variable cannot help.
         */
        const val TWO_FACTOR_TOKEN_NOTE =
            "$ENV_CONSOLE_2FA_TOKEN is a time-based one-time code: a fixed value stops working within about a " +
                "minute, so use a service account without two-factor authentication or restart the server with a fresh code."

        private val FLAG_TRUE = setOf("1", "true", "yes", "on")
        private val FLAG_FALSE = setOf("0", "false", "no", "off")
        private val HOST_PRESENT = Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/:?#@\\s]+")

        /**
         * The boolean environment variable [name], whose raw value is [value]. Unset or blank is false.
         * Every on/off variable goes through here (in [fromEnv], via its local `flag`).
         *
         * Anything outside those two lists fails startup rather than reading as false: most of these
         * flags tighten ([ENV_READ_ONLY], [ENV_DISABLE_EXPORT], the update switches), so a lenient parse
         * turned `INSIGHTVM_READ_ONLY=y` into every mutating tool registered, silently. A malformed URL
         * or region already stops the server; a malformed safety flag now does too. The message names
         * the variable only, like every other configuration error.
         */
        internal fun parseFlag(name: String, value: String?): Boolean {
            val normalized = value?.trim()?.lowercase()
            return when {
                normalized.isNullOrEmpty() -> false
                normalized in FLAG_TRUE -> true
                normalized in FLAG_FALSE -> false
                else -> throw IllegalArgumentException("$name must be one of 1/true/yes/on or 0/false/no/off.")
            }
        }

        /**
         * [raw] with surrounding whitespace trimmed, refused unless every remaining character is visible
         * ASCII (0x21..0x7E). For secrets that become an HTTP header value (`X-Api-Key`, `Token`) or are
         * compared with one (the `--http` bearer token).
         *
         * Trimming covers pasted padding and the CR that a CRLF env file leaves on each value; a stored
         * bearer token padded that way could never match, because the `Authorization` parser trims what
         * a client presents. What trimming cannot fix must fail here, at startup, where only the operator
         * sees it: Ktor and OkHttp refuse an illegal header character at request time with an exception
         * that quotes the whole value, and that message used to reach the model as a tool error. The
         * error names the variable and a 1-based position in the value as set, never the value itself.
         */
        internal fun headerSafeSecret(name: String, raw: String): String {
            val leading = raw.indexOfFirst { !it.isWhitespace() }.coerceAtLeast(0)
            val value = raw.trim()
            val bad = value.indexOfFirst { it !in '!'..'~' }
            require(bad < 0) {
                "$name contains a character that cannot be sent in an HTTP header (position ${leading + bad + 1})."
            }
            return value
        }

        internal fun csv(value: String?): List<String> =
            value?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

        fun fromEnv(env: Map<String, String> = System.getenv()): Config {
            fun get(name: String): String? = env[name]?.takeIf { it.isNotBlank() }
            fun flag(name: String): Boolean = parseFlag(name, env[name])

            // Every flag is read up front, so a malformed one fails startup whether or not the setting
            // it belongs to is in use.
            val allowHttp = flag(ENV_ALLOW_HTTP)
            val insecureTls = flag(ENV_CONSOLE_INSECURE_TLS)
            val filter = ToolFilter(
                readOnly = flag(ENV_READ_ONLY),
                tags = csv(env[ENV_TAGS]).toSet(),
                excludeTags = csv(env[ENV_EXCLUDE_TAGS]).toSet(),
                allowAdminCommands = flag(ENV_ALLOW_ADMIN_COMMANDS),
                allowSecretTools = flag(ENV_ALLOW_SECRET_TOOLS),
            )
            val keepRecordLinks = flag(ENV_KEEP_RECORD_LINKS)
            val exportDisabled = flag(ENV_DISABLE_EXPORT)
            val updateCheckDisabled = flag(ENV_DISABLE_UPDATE_CHECK)
            val autoUpdateDisabled = flag(ENV_DISABLE_AUTO_UPDATE)

            val console = consoleFromEnv(env, allowHttp = allowHttp, insecureTls = insecureTls)
            val cloud = get(ENV_API_KEY)?.let { key ->
                val region = Region.fromCode(get(ENV_REGION) ?: DEFAULT_REGION)
                val base = get(ENV_CLOUD_BASE_URL)?.trimEnd('/') ?: "https://${region.code}.api.insight.rapid7.com/vm"
                // The API key travels on every request; never let an override downgrade it to cleartext by accident.
                require(base.startsWith("https://") || (allowHttp && base.startsWith("http://"))) {
                    "$ENV_CLOUD_BASE_URL must use https (set $ENV_ALLOW_HTTP=1 to permit cleartext http)."
                }
                CloudConfig(apiKey = headerSafeSecret(ENV_API_KEY, key), region = region, baseUrl = base)
            }
            if (cloud == null && get(ENV_REGION) != null && console == null) {
                throw IllegalStateException("$ENV_REGION is set but $ENV_API_KEY is missing.")
            }

            val timeout = get(ENV_TIMEOUT_MS)?.toLongOrNull()?.takeIf { it > 0 } ?: DEFAULT_TIMEOUT_MS
            val maxBytes = (get(ENV_MAX_RESPONSE_BYTES)?.toLongOrNull()?.takeIf { it > 0 } ?: DEFAULT_MAX_RESPONSE_BYTES)
                .coerceAtMost(MAX_RESPONSE_BYTES_CEILING)
            val maxResultChars = (get(ENV_MAX_RESULT_CHARS)?.toIntOrNull()?.takeIf { it > 0 } ?: DEFAULT_MAX_RESULT_CHARS)
                .coerceIn(MIN_MAX_RESULT_CHARS, MAX_MAX_RESULT_CHARS)
            val origins = csv(env[ENV_HTTP_ALLOWED_ORIGINS]).filter { it != "*" }

            return Config(
                console = console,
                cloud = cloud,
                requestTimeoutMillis = timeout,
                maxResponseBytes = maxBytes,
                maxResultChars = maxResultChars,
                keepRecordLinks = keepRecordLinks,
                defaultPageSize = (get(ENV_DEFAULT_PAGE_SIZE)?.toIntOrNull()?.takeIf { it > 0 } ?: PagingDefaults.DEFAULT_PAGE_SIZE)
                    .coerceIn(1, PagingDefaults.MAX_PAGE_SIZE),
                spoolDirectory = get(ENV_SPOOL_DIR),
                spoolRetentionHours = (get(ENV_SPOOL_RETENTION_HOURS)?.toIntOrNull()?.takeIf { it >= 0 } ?: DEFAULT_SPOOL_RETENTION_HOURS),
                exportDisabled = exportDisabled,
                httpAuthToken = get(ENV_MCP_AUTH_TOKEN)?.let { headerSafeSecret(ENV_MCP_AUTH_TOKEN, it) },
                httpAllowedOrigins = origins,
                filter = filter,
                updateCheckDisabled = updateCheckDisabled,
                autoUpdateDisabled = autoUpdateDisabled,
            )
        }

        private fun consoleFromEnv(env: Map<String, String>, allowHttp: Boolean, insecureTls: Boolean): ConsoleConfig? {
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
                baseUrl = normalizeConsoleUrl(url, allowHttp = allowHttp),
                username = user,
                password = password,
                twoFactorToken = get(ENV_CONSOLE_2FA_TOKEN)?.let { headerSafeSecret(ENV_CONSOLE_2FA_TOKEN, it) },
                caCertPath = get(ENV_CONSOLE_CA_CERT),
                insecureTls = insecureTls,
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
