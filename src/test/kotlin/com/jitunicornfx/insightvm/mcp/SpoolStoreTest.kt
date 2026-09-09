package com.jitunicornfx.insightvm.mcp

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SpoolStoreTest {

    private val dir: Path = createTempDirectory("spool-test")
    private val store = SpoolStore(dir)

    @AfterTest
    fun cleanup() {
        dir.toFile().deleteRecursively()
    }

    @Test
    fun `prepare creates the directory and drops the warning readme once`() {
        val nested = dir.resolve("a").resolve("b")
        val s = SpoolStore(nested)
        s.prepare()
        assertTrue(Files.isDirectory(nested))
        val readme = nested.resolve(SpoolStore.README_NAME)
        assertTrue(Files.isRegularFile(readme))
        val text = Files.readString(readme)
        assertContains(text, "UNTRUSTED THIRD-PARTY DATA")
        assertContains(text, Config.ENV_SPOOL_RETENTION_HOURS)

        // Idempotent: a second prepare must not overwrite an edited README.
        Files.writeString(readme, "edited")
        s.prepare()
        assertEquals("edited", Files.readString(readme))
    }

    @Test
    fun `spool files are unique, contained and suffixed`() {
        val a = store.newSpoolFile("get_assets")
        val b = store.newSpoolFile("get_assets")
        assertNotEquals(a, b, "two exports must never share a file")
        for (f in listOf(a, b)) {
            assertTrue(Files.isRegularFile(f))
            assertTrue(f.fileName.toString().startsWith(SpoolStore.FILE_PREFIX))
            assertTrue(f.fileName.toString().endsWith(SpoolStore.FILE_SUFFIX))
            assertContains(f.fileName.toString(), "get-assets")
            assertTrue(f.normalize().startsWith(dir.normalize()), "must stay inside the spool directory")
        }
        val bin = store.newSpoolFile("get_logs", SpoolStore.BINARY_SUFFIX)
        assertTrue(bin.fileName.toString().endsWith(SpoolStore.BINARY_SUFFIX))
    }

    @Test
    fun `a hostile label cannot escape the directory`() {
        for (label in listOf("../../etc/passwd", "..", ".", "C:\\Windows\\System32", "a/b\\c:d", "\u0000nul", "   ", "CON")) {
            val f = store.newSpoolFile(label)
            assertTrue(f.normalize().startsWith(dir.normalize()), "escaped with label '$label' -> $f")
            assertEquals(dir.normalize(), f.normalize().parent, "must be a direct child")
            val name = f.fileName.toString()
            assertFalse(name.contains(".."), name)
            assertFalse(name.contains("/") || name.contains("\\"), name)
        }
        // The sanitiser itself, directly.
        assertEquals("etc-passwd", store.sanitizeLabel("../../etc/passwd"))
        assertEquals("export", store.sanitizeLabel("..."), "an all-punctuation label falls back")
        assertEquals("a-b-c-d", store.sanitizeLabel("a/b\\c:d"))
        assertEquals(40, store.sanitizeLabel("x".repeat(200)).length)
    }

    @Test
    fun `manifestFor swaps the suffix for every kind of spool file`() {
        val nd = store.newSpoolFile("get_assets")
        assertTrue(store.manifestFor(nd).fileName.toString().endsWith(SpoolStore.MANIFEST_SUFFIX))
        assertFalse(store.manifestFor(nd).fileName.toString().contains(SpoolStore.FILE_SUFFIX))
        val bin = store.newSpoolFile("get_logs", SpoolStore.BINARY_SUFFIX)
        assertTrue(store.manifestFor(bin).fileName.toString().endsWith(SpoolStore.MANIFEST_SUFFIX))
        assertEquals(dir.normalize(), store.manifestFor(nd).normalize().parent)
    }

    @Test
    fun `sweepStale removes only our own aged files`() {
        val old = store.newSpoolFile("old")
        val oldManifest = store.manifestFor(old).also { Files.writeString(it, "{}") }
        val fresh = store.newSpoolFile("fresh")
        val foreign = dir.resolve("someone-elses-notes.ndjson").also { Files.writeString(it, "x") }
        val readme = dir.resolve(SpoolStore.README_NAME)

        val hour = 3_600_000L
        val now = System.currentTimeMillis()
        for (f in listOf(old, oldManifest)) f.toFile().setLastModified(now - 25 * hour)
        foreign.toFile().setLastModified(now - 1000 * hour)
        readme.toFile().setLastModified(now - 1000 * hour)

        store.sweepStale(24 * hour, now)

        assertFalse(Files.exists(old), "an aged export is swept")
        assertFalse(Files.exists(oldManifest), "its manifest goes with it")
        assertTrue(Files.exists(fresh), "a recent export survives")
        assertTrue(Files.exists(foreign), "files that are not ours are never touched")
        assertTrue(Files.exists(readme), "the warning README is never swept")

        // A missing directory is a no-op, not a throw.
        SpoolStore(dir.resolve("nope")).sweepStale(hour)
    }

    @Test
    fun `usableSpace reports the volume and MIN_FREE_BYTES is a real reserve`() {
        val free = store.usableSpace()
        assertTrue(free == null || free >= 0)
        assertEquals(256L * 1024 * 1024, SpoolStore.MIN_FREE_BYTES)
    }

    @Test
    fun `resolve honours a configured directory and falls back to a private default`() {
        assertEquals(dir, SpoolStore.resolve(dir.toString()).directory)
        assertEquals(SpoolStore.defaultDirectory(), SpoolStore.resolve(null).directory)
        assertEquals(SpoolStore.defaultDirectory(), SpoolStore.resolve("   ").directory)
        // The default is per-user, never the working directory or the JAR's own directory.
        assertContains(SpoolStore.defaultDirectory().toString(), "rapid7-insightvm-mcp")
    }

    @Test
    fun `the installed store is process-wide and replaceable`() {
        val original = SpoolStore.active
        try {
            SpoolStore.install(store)
            assertEquals(dir, SpoolStore.active.directory)
        } finally {
            SpoolStore.install(original)
        }
    }
}
