package com.jitunicornfx.insightvm.mcp

import io.ktor.client.*
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Checks the project's GitHub repository for a newer release than the running server.
 *
 * Design constraints, in order of importance:
 *  - **Never blocks or breaks startup.** Every failure path (offline, rate limited, GitHub outage,
 *    malformed payload, timeout) resolves to "no update known" rather than an exception.
 *  - **Sends no credentials.** The releases endpoint is public and the InsightVM `X-Api-Key` must
 *    never leave Rapid7 hosts, so this uses its own unauthenticated client — not [Rapid7Client].
 *  - **Opt-out.** Operators can disable the network call entirely via [Config.ENV_DISABLE_UPDATE_CHECK].
 */
object UpdateChecker {

    /** Public GitHub API endpoint for the newest published (non-draft, non-prerelease) release. */
    const val LATEST_RELEASE_URL =
        "https://api.github.com/repos/jitunicornfx/Rapid7-InsightVM-MCP/releases/latest"

    /** Human-facing releases page, included in the notification so a user can act on it. */
    const val RELEASES_PAGE_URL = "https://github.com/jitunicornfx/Rapid7-InsightVM-MCP/releases"

    /** How long to wait on the check before giving up; startup must not stall on a slow network. */
    const val TIMEOUT_MS = 5_000L

    /** Longest release tag accepted. A real version is far shorter; anything longer is not a version. */
    const val MAX_TAG_LENGTH = 64

    /**
     * Largest response body inspected. A release payload is a few KB; anything beyond this is
     * refused, and its transfer is stopped at this many bytes rather than buffered, so a hostile or
     * runaway endpoint cannot exhaust memory.
     */
    const val MAX_BODY_BYTES = 1_000_000L

    /**
     * The only shape a release tag may take. This is an allow-list, not a sanitizer, and it is the
     * security boundary for the whole feature: the tag is remote, attacker-influenceable input that
     * ends up in text delivered to the LLM client, so anything that is not literally a version string
     * (digits, dots, an optional `v` prefix, an optional short pre-release/build suffix) is rejected
     * outright rather than escaped. In particular this admits no whitespace, newlines, control or
     * ANSI-escape characters, and no free-form prose.
     */
    private val VERSION_TAG = Regex("""^[vV]?\d{1,6}(\.\d{1,6}){0,3}([-+][0-9A-Za-z.]{1,32})?$""")

    /** Hosts a release asset may be downloaded from. GitHub serves release binaries off its CDN. */
    private val ALLOWED_DOWNLOAD_HOSTS = setOf(
        "github.com",
        "api.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    )

    /** A release asset filename: a bare, safe filename — never a path. */
    private val ASSET_NAME = Regex("""^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.jar$""")

    /** GitHub's asset integrity digest, e.g. `sha256:abc...` (64 lowercase hex characters). */
    private val ASSET_DIGEST = Regex("""^sha256:[0-9a-f]{64}$""")

    /** Largest release binary accepted, a sanity bound well above the real ~19MB artifact. */
    const val MAX_ASSET_BYTES = 200_000_000L

    /**
     * A downloadable release binary, with everything needed to fetch and *verify* it.
     *
     * Every field is validated at parse time ([parseAsset]) because this drives code installation:
     * [name] is a bare filename (never a path), [downloadUrl] is HTTPS on a GitHub-owned host, and
     * [sha256] is the mandatory integrity anchor — an asset without a usable digest is not offered.
     */
    data class ReleaseAsset(
        val name: String,
        val downloadUrl: String,
        val sha256: String,
        val sizeBytes: Long,
    )

    /** Whether [url] is an HTTPS URL on a host we are willing to download a release binary from. */
    internal fun isAllowedDownloadUrl(url: String): Boolean {
        val parsed = runCatching { Url(url) }.getOrNull() ?: return false
        if (parsed.protocol != URLProtocol.HTTPS) return false
        val host = parsed.host.lowercase()
        // Exact host match only — no suffix matching, so "objects.githubusercontent.com.evil.tld"
        // and userinfo tricks ("https://github.com@evil.tld/x") cannot pass.
        return host in ALLOWED_DOWNLOAD_HOSTS
    }

    /**
     * Extract the single runnable fat-JAR asset from a release payload, or null when the release has
     * no asset that is safe to install. Rejects assets whose name is not a plain `.jar` filename,
     * whose URL is not HTTPS on a GitHub host, whose size is absent/implausible, or — critically —
     * that carry no `sha256:` digest, since the digest is what makes the download verifiable.
     */
    internal fun parseAsset(body: String): ReleaseAsset? {
        if (body.length > MAX_BODY_BYTES) return null
        val json = runCatching { JsonCodec.compact.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        val assets = json["assets"] as? JsonArray ?: return null
        return assets.asSequence()
            .mapNotNull { it as? JsonObject }
            .mapNotNull { asset ->
                val name = (asset["name"] as? JsonPrimitive)?.contentOrNull?.trim() ?: return@mapNotNull null
                val url = (asset["browser_download_url"] as? JsonPrimitive)?.contentOrNull?.trim() ?: return@mapNotNull null
                val digest = (asset["digest"] as? JsonPrimitive)?.contentOrNull?.trim()?.lowercase() ?: return@mapNotNull null
                val size = (asset["size"] as? JsonPrimitive)?.contentOrNull?.toLongOrNull() ?: return@mapNotNull null
                if (!ASSET_NAME.matches(name)) return@mapNotNull null
                if (!isAllowedDownloadUrl(url)) return@mapNotNull null
                if (!ASSET_DIGEST.matches(digest)) return@mapNotNull null
                if (size <= 0 || size > MAX_ASSET_BYTES) return@mapNotNull null
                ReleaseAsset(name, url, digest.removePrefix("sha256:"), size)
            }
            .firstOrNull { it.name.endsWith("-all.jar") }
    }

    /** The outcome of a check. [latestVersion] is only set when a newer release was found. */
    data class Result(
        val updateAvailable: Boolean,
        val currentVersion: String,
        val latestVersion: String? = null,
        val releaseUrl: String = RELEASES_PAGE_URL,
        /** The verified-downloadable binary for [latestVersion], when the release publishes one. */
        val asset: ReleaseAsset? = null,
        /**
         * The newest release GitHub named, whether or not it is newer, having passed the same
         * allow-list as [latestVersion]. Null when the check got no usable answer (offline, rate
         * limited, a malformed payload), which is how "up to date" is told apart from "unknown".
         */
        val latestRelease: String? = latestVersion,
    ) {
        /** The message surfaced to the MCP client. */
        fun message(): String =
            if (updateAvailable) {
                "A new version of the Rapid7 InsightVM MCP server is available: " +
                    "$latestVersion (currently running $currentVersion). Download: $releaseUrl"
            } else {
                "Rapid7 InsightVM MCP server $currentVersion is up to date."
            }
    }

    /**
     * Compare two dotted version strings numerically, ignoring a leading `v` and any pre-release
     * suffix (e.g. `1.2.3-rc1` compares as `1.2.3`). Returns a negative number when [a] precedes
     * [b], zero when they are equivalent, positive when [a] is newer. Missing components count as 0,
     * so `0.1` and `0.1.0` are equal. Non-numeric components are treated as 0 rather than throwing.
     */
    internal fun compareVersions(a: String, b: String): Int {
        fun parts(v: String): List<Int> =
            v.trim().removePrefix("v").removePrefix("V")
                .substringBefore('-').substringBefore('+')
                .split('.')
                .map { it.trim().toIntOrNull() ?: 0 }

        val pa = parts(a)
        val pb = parts(b)
        for (i in 0 until maxOf(pa.size, pb.size)) {
            val cmp = (pa.getOrElse(i) { 0 }).compareTo(pb.getOrElse(i) { 0 })
            if (cmp != 0) return cmp
        }
        return 0
    }

    /**
     * Extract the release tag from a GitHub release payload, **accepting it only if it is a
     * well-formed version string** ([VERSION_TAG], at most [MAX_TAG_LENGTH] characters).
     *
     * This validation is deliberately strict because the returned value crosses a trust boundary:
     * it is remote content that ends up in a notification delivered to an LLM client (and on the
     * operator's terminal). An unvalidated tag would let anyone able to influence the response body
     * inject arbitrary text — including instructions — straight into the model's context. A tag that
     * is not a version is treated exactly like an unparsable payload: no update.
     *
     * Only `tag_name` is read. The free-form `name` (release title) is intentionally *not* used as a
     * fallback: GitHub always populates `tag_name` for a release, and the title is arbitrary prose.
     */
    internal fun parseLatestTag(body: String): String? {
        if (body.length > MAX_BODY_BYTES) return null
        val json = runCatching { JsonCodec.compact.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        val tag = (json["tag_name"] as? JsonPrimitive)?.contentOrNull?.trim() ?: return null
        return tag.takeIf { it.length <= MAX_TAG_LENGTH && VERSION_TAG.matches(it) }
    }

    /**
     * Decide the [Result] from a fetched release [body]. Split out from the network call so the
     * comparison logic is directly testable and so an unparsable payload degrades to "no update".
     */
    internal fun evaluate(body: String?, currentVersion: String): Result {
        val latest = body?.let { parseLatestTag(it) }
            ?: return Result(updateAvailable = false, currentVersion = currentVersion)
        val newer = compareVersions(latest, currentVersion) > 0
        val display = latest.removePrefix("v").removePrefix("V")
        return Result(
            updateAvailable = newer,
            currentVersion = currentVersion,
            latestVersion = if (newer) display else null,
            asset = if (newer) parseAsset(body) else null,
            latestRelease = display,
        )
    }

    /**
     * Fetch the latest release and report whether it is newer than [currentVersion].
     *
     * Returns a "no update" [Result] on any failure — this is a best-effort convenience, never a
     * reason to fail startup. [engine] is injectable so tests can drive it without network access.
     */
    suspend fun check(
        currentVersion: String = SERVER_VERSION,
        engine: HttpClientEngine? = null,
    ): Result =
        // The ENTIRE body is guarded, not just the network call: parsing and version comparison run
        // on remote input, and this function promises never to throw. An escaping exception would
        // otherwise propagate out of the coroutine that starts the check and tear down the server.
        runCatching {
            val body = run {
                val http = if (engine != null) HttpClient(engine) { configure() } else HttpClient(OkHttp) { configure() }
                http.use { client ->
                    // execute { }, not get(): get() buffers the ENTIRE body in memory before
                    // returning, so no check made afterwards could bound what was read.
                    client.prepareGet(LATEST_RELEASE_URL) {
                        header(HttpHeaders.Accept, "application/vnd.github+json")
                        header("X-GitHub-Api-Version", "2022-11-28")
                        // GitHub requires a User-Agent; identify the server without leaking anything.
                        header(HttpHeaders.UserAgent, "$SERVER_NAME/$currentVersion")
                    }.execute { response ->
                        val declaredLength = response.contentLength()
                        when {
                            response.status.value !in 200..299 -> null
                            // An early exit only. api.github.com answers gzipped, and OkHttp strips
                            // Content-Length when it decodes that transparently, so this rarely fires;
                            // the streamed cap below is the bound that actually holds.
                            declaredLength != null && declaredLength > MAX_BODY_BYTES -> null
                            else -> {
                                val (bytes, truncated) = Rapid7Client.readCapped(response.bodyAsChannel(), MAX_BODY_BYTES)
                                if (truncated) null else bytes.decodeToString()
                            }
                        }
                    }
                }
            }
            evaluate(body, currentVersion)
        }.getOrElse { Result(updateAvailable = false, currentVersion = currentVersion) }

    private fun HttpClientConfig<*>.configure() {
        expectSuccess = false
        // Do not auto-follow redirects, matching Rapid7Client. The response body is parsed and its
        // contents surface to the LLM client, so a 3xx must not be able to steer this fetch to a
        // host other than the fixed GitHub endpoint above.
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = TIMEOUT_MS
            connectTimeoutMillis = TIMEOUT_MS
            socketTimeoutMillis = TIMEOUT_MS
        }
    }
}
