package com.jitunicornfx.insightvm.mcp

import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BuildInfoTest {

    private fun props(vararg pairs: Pair<String, String>) = Properties().apply {
        pairs.forEach { (k, v) -> setProperty(k, v) }
    }

    @Test
    fun `an absent resource falls back to the hardcoded version`() {
        val data = BuildInfo.parse(null)
        assertEquals(BuildInfo.FALLBACK_VERSION, data.version)
        assertFalse(data.fromGeneratedResource, "the fallback must be distinguishable from a real read")
        assertNull(data.gitSha)
        assertFalse(data.gitDirty)
    }

    @Test
    fun `a malformed version falls back rather than being reported`() {
        assertEquals(BuildInfo.FALLBACK_VERSION, BuildInfo.parse(props("version" to "not a version")).version)
        assertEquals(BuildInfo.FALLBACK_VERSION, BuildInfo.parse(props("version" to "")).version)
    }

    @Test
    fun `a version carrying a newline can never reach the User-Agent`() {
        // The version is interpolated into an outbound User-Agent header and the MCP Implementation
        // block, so a hand-edited or corrupted resource must not be able to inject a header line.
        val data = BuildInfo.parse(props("version" to "1.0\ninjected: header"))
        assertEquals(BuildInfo.FALLBACK_VERSION, data.version)
        assertFalse("\n" in data.version)
    }

    @Test
    fun `a bad git sha is dropped without losing the version`() {
        val data = BuildInfo.parse(props("version" to "1.2.3", "git.sha" to "ZZZNOTHEX"))
        assertEquals("1.2.3", data.version)
        assertNull(data.gitSha, "an invalid sha must be dropped, not reported")
        assertTrue(data.fromGeneratedResource)
    }

    @Test
    fun `a bad timestamp is dropped without losing the version`() {
        val data = BuildInfo.parse(
            props("version" to "1.2.3", "git.commitTime" to "yesterday", "build.generatedAt" to "soon"),
        )
        assertEquals("1.2.3", data.version)
        assertNull(data.gitCommitTime)
        assertNull(data.generatedAt)
    }

    @Test
    fun `a full resource parses every field`() {
        val data = BuildInfo.parse(
            props(
                "version" to "0.3.1",
                "git.sha" to "A1B2C3D4E5F6",
                "git.commitTime" to "2026-09-08T14:11:03-04:00",
                "git.dirty" to "true",
                "build.generatedAt" to "2026-09-09T18:22:41Z",
            ),
        )
        assertEquals("0.3.1", data.version)
        assertEquals("a1b2c3d4e5f6", data.gitSha, "a sha is normalized to lower case")
        assertEquals("2026-09-08T14:11:03-04:00", data.gitCommitTime)
        assertTrue(data.gitDirty)
        assertEquals("2026-09-09T18:22:41Z", data.generatedAt)
        assertTrue(data.fromGeneratedResource)
    }

    @Test
    fun `a prerelease version is accepted`() {
        assertEquals("1.2.3-rc.1", BuildInfo.parse(props("version" to "1.2.3-rc.1")).version)
    }

    @Test
    fun `the fallback constant has not drifted from the generated version`() {
        // The drift guard. Under ./gradlew test the generated resource is always present, so this
        // compares the hardcoded fallback against build.gradle.kts's version by proxy. It fails the
        // moment someone bumps the Gradle version without updating BuildInfo.FALLBACK_VERSION.
        assertTrue(
            BuildInfo.fromGeneratedResource,
            "the generated resource should be on the test classpath — is :generateBuildInfo wired in?",
        )
        assertEquals(
            BuildInfo.FALLBACK_VERSION,
            BuildInfo.version,
            "BuildInfo.FALLBACK_VERSION has drifted from build.gradle.kts's version",
        )
    }

    @Test
    fun `SERVER_VERSION reports the generated build version`() {
        assertEquals(BuildInfo.version, SERVER_VERSION)
    }
}
