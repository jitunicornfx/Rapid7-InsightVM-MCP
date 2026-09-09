package com.jitunicornfx.insightvm.mcp

import java.time.Instant
import java.time.OffsetDateTime
import java.util.Properties

/**
 * What this build IS: the version, and the commit it came from.
 *
 * Populated from a resource Gradle's `:generateBuildInfo` writes from `build.gradle.kts`'s
 * `version`, which is the single source of truth. [FALLBACK_VERSION] covers the case where that
 * resource is absent — loose class files, or an IDE build that skipped Gradle. `BuildInfoTest`
 * asserts the fallback equals the generated value, so it cannot silently rot.
 *
 * Every value is re-validated after loading. The version ends up in an outbound HTTP `User-Agent`
 * header and in the MCP `Implementation` block the client sees, so a corrupted or hand-edited
 * resource must not be able to inject a newline or arbitrary text into either.
 *
 * Note on [generatedAt]: it records when the build info was last *regenerated* — the last time the
 * version, commit or dirty flag changed — not the last time the project was built. Making it exact
 * would require feeding a wall clock into the Gradle task's inputs, which would leave the task, and
 * everything downstream of it, out of date on every build. [gitCommitTime] is the precise answer.
 */
object BuildInfo {

    internal const val RESOURCE_PATH = "/META-INF/insightvm-mcp-build.properties"

    /** Mirrors `version` in build.gradle.kts. Used only when the generated resource is missing. */
    const val FALLBACK_VERSION: String = "0.1.0"

    /** Same shape as UpdateChecker's release-tag allow-list: a version string and nothing else. */
    private val VERSION = Regex("""^\d{1,6}(\.\d{1,6}){0,3}([-+][0-9A-Za-z.]{1,32})?$""")
    private val SHA = Regex("""^[0-9a-f]{7,40}$""")

    /** Everything the generated resource can tell us. A null field means "not known". */
    internal data class Data(
        val version: String,
        val gitSha: String? = null,
        val gitCommitTime: String? = null,
        val gitDirty: Boolean = false,
        val generatedAt: String? = null,
        /** False when the resource was absent or unusable and [FALLBACK_VERSION] applied. */
        val fromGeneratedResource: Boolean = false,
    )

    /**
     * Project [props] onto validated [Data].
     *
     * Split out from [load] so the absent- and malformed-resource paths are testable: under
     * `./gradlew test` the generated resource is always on the runtime classpath, so a test can
     * never observe its absence naturally.
     */
    internal fun parse(props: Properties?): Data {
        if (props == null) return Data(FALLBACK_VERSION)
        // A bad version discards the whole file; a bad individual field is simply dropped.
        val version = props.getProperty("version")?.trim()?.takeIf { VERSION.matches(it) }
            ?: return Data(FALLBACK_VERSION)
        return Data(
            version = version,
            gitSha = props.getProperty("git.sha")?.trim()?.lowercase()?.takeIf { SHA.matches(it) },
            gitCommitTime = props.getProperty("git.commitTime")?.trim()
                ?.takeIf { runCatching { OffsetDateTime.parse(it) }.isSuccess },
            gitDirty = props.getProperty("git.dirty")?.trim()?.toBooleanStrictOrNull() ?: false,
            generatedAt = props.getProperty("build.generatedAt")?.trim()
                ?.takeIf { runCatching { Instant.parse(it) }.isSuccess },
            fromGeneratedResource = true,
        )
    }

    private fun load(): Data = parse(
        runCatching {
            BuildInfo::class.java.getResourceAsStream(RESOURCE_PATH)?.use { stream ->
                Properties().apply { load(stream.reader(Charsets.UTF_8)) }
            }
        }.getOrNull(),
    )

    private val data: Data = load()

    val version: String get() = data.version
    val gitSha: String? get() = data.gitSha
    val gitCommitTime: String? get() = data.gitCommitTime
    val gitDirty: Boolean get() = data.gitDirty
    val generatedAt: String? get() = data.generatedAt

    /** False when the generated resource was missing and [FALLBACK_VERSION] is what is reported. */
    val fromGeneratedResource: Boolean get() = data.fromGeneratedResource
}
