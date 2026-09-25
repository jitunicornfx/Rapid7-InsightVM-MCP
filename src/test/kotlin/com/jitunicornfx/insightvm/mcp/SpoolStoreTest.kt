package com.jitunicornfx.insightvm.mcp

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.io.IOException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryFlag
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.util.EnumSet
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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

    // ------------------------------------------------------------------ directory and file safety

    /** A directory the test makes itself, private on POSIX whatever the umask, as one this server made would be. */
    private fun privateDir(name: String): Path = Files.createDirectory(dir.resolve(name)).also {
        if ("posix" in it.fileSystem.supportedFileAttributeViews()) {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
    }

    /** Regression: the manifest was written with Files.writeString, which replaces whatever is already at its path. */
    @Test
    fun `a manifest never replaces a file already at its path`() {
        val spool = store.newSpoolFile("get_assets")
        val squatter = store.manifestFor(spool).also { Files.writeString(it, "planted") }
        assertFailsWith<FileAlreadyExistsException> { store.writeManifest(spool, "{}") }
        assertEquals("planted", Files.readString(squatter))
    }

    /**
     * Regression: the manifest and the README were written with Files.writeString, which follows a
     * symlink planted at their path and writes wherever it points. Creating a symlink needs a privilege
     * on Windows, so there the test runs only where the account holds it.
     */
    @Test
    fun `neither the manifest nor the README is written through a planted symlink`() {
        val outside = createTempDirectory("spool-outside")
        try {
            val target = outside.resolve("target.txt").also { Files.writeString(it, "original") }
            val spool = store.newSpoolFile("get_assets")
            val link = store.manifestFor(spool)
            assumeTrue(runCatching { Files.createSymbolicLink(link, target) }.isSuccess, "creating a symbolic link needs a privilege here")
            assertFailsWith<IOException> { store.writeManifest(spool, "{}") }
            assertEquals("original", Files.readString(target), "the link target is untouched")

            // A dangling link where the README goes: following it would create a file wherever it points.
            val other = privateDir("other")
            val nowhere = outside.resolve("readme-target.txt")
            Files.createSymbolicLink(other.resolve(SpoolStore.README_NAME), nowhere)
            SpoolStore(other).prepare()
            assertFalse(Files.exists(nowhere), "the README was written through the link")
        } finally {
            outside.toFile().deleteRecursively()
        }
    }

    /**
     * Regression: prepare() chmodded the directory on every call, including one the operator named that
     * already existed: INSIGHTVM_SPOOL_DIR=/tmp run as root left /tmp rwx------.
     */
    @Test
    @EnabledOnOs(OS.LINUX, OS.MAC)
    fun `a directory that already existed is never chmodded`() {
        val existing = Files.createDirectory(dir.resolve("existing"))
        val shared = PosixFilePermissions.fromString("rwxr-xr-x")
        Files.setPosixFilePermissions(existing, shared)
        val file = SpoolStore(existing).newSpoolFile("get_assets")
        assertEquals(shared, Files.getPosixFilePermissions(existing), "the operator's directory keeps its mode")
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file))
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(existing.resolve(SpoolStore.README_NAME)))
    }

    @Test
    @EnabledOnOs(OS.LINUX, OS.MAC)
    fun `a directory this store creates is born rwx------`() {
        val created = dir.resolve("a").resolve("b")
        SpoolStore(created).prepare()
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(created))
    }

    /**
     * Regression: a directory the store failed to secure was only warned about, and written into anyway.
     * One that another account can write to is refused: that account could swap or link a file between
     * an export writing it and the operator reading it.
     */
    @Test
    @EnabledOnOs(OS.LINUX, OS.MAC)
    fun `a directory other accounts can write to is refused, and a binary spill says why`() {
        for ((i, mode) in listOf("rwxrwxrwx", "rwxrwx---", "rwx----w-").withIndex()) {
            val open = Files.createDirectory(dir.resolve("open-$i"))
            Files.setPosixFilePermissions(open, PosixFilePermissions.fromString(mode))
            val s = SpoolStore(open)
            val e = assertFailsWith<UnsafeSpoolDirectoryException>(mode) { s.prepare() }
            assertContains(e.message!!, "other than its owner")
            assertEquals(PosixFilePermissions.fromString(mode), Files.getPosixFilePermissions(open), "never chmodded")
            assertEquals(0, open.toFile().list()!!.size, "nothing is written into it")

            val descriptor = ResponseSanitizer.describeBinary(ByteArray(8_192), "application/zip", false, s, "get_logs")
            assertContains(descriptor, "\"pathError\": \"the spool directory")
            assertFalse(descriptor.contains("\"path\":"), descriptor)
        }
    }

    /**
     * On Windows a directory this store creates is born with one inheritable entry for its owner, so
     * neither it nor a file created in it is ever open to another account. Before, it inherited
     * whatever its parent allowed.
     */
    @Test
    @EnabledOnOs(OS.WINDOWS)
    fun `on Windows a directory this store creates is private to its owner, and so are its files`() {
        val created = dir.resolve("a").resolve("b")
        val s = SpoolStore(created)
        val file = s.newSpoolFile("get_assets")
        val owner = Files.getOwner(created)
        val dirAcl = Files.getFileAttributeView(created, AclFileAttributeView::class.java).acl
        assertEquals(listOf(owner), dirAcl.map { it.principal() }.distinct(), "only the owner has an entry: $dirAcl")
        assertTrue(dirAcl.all { it.type() == AclEntryType.ALLOW }, dirAcl.toString())
        assertTrue(dirAcl.any { it.flags().containsAll(listOf(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)) }, dirAcl.toString())
        val fileAcl = Files.getFileAttributeView(file, AclFileAttributeView::class.java).acl
        assertEquals(listOf(owner), fileAcl.map { it.principal() }.distinct(), "its files inherit only that entry: $fileAcl")
        assertEquals(listOf("b"), created.parent.toFile().list()!!.toList(), "the owner probe is removed")

        // The owner keeps every right the store needs: write, read, age and sweep.
        Files.writeString(file, "x")
        assertEquals("x", Files.readString(file))
        assertTrue(file.toFile().setLastModified(System.currentTimeMillis() - 48 * 3_600_000L))
        s.sweepStale(24 * 3_600_000L)
        assertFalse(Files.exists(file), "swept")
    }

    /**
     * Regression: run elevated, a new file's owner is the Administrators GROUP, so the spool was born
     * private to that group. A later run of the same user without elevation carries Administrators only
     * as a deny-only group, so it could no longer write into its own spool: every export and binary
     * spill failed until someone repaired the ACL by hand. A group owner now falls back to the parent's
     * ACL, which is what every spool had before it could be born private.
     *
     * The probe is overridden with the real Administrators principal to stand in for an elevated token;
     * this test process itself runs without elevation, which is exactly the later run that was locked out.
     */
    @Test
    @EnabledOnOs(OS.WINDOWS)
    fun `on Windows an elevated first run does not lock later runs out of the spool`() {
        val admins = runCatching {
            dir.fileSystem.userPrincipalLookupService.lookupPrincipalByGroupName("Administrators")
        }.getOrNull()
        assumeTrue(admins != null, "the Administrators group name is localised on this system")
        val created = dir.resolve("spool")
        val elevated = object : SpoolStore(created) {
            override fun probeOwner(dir: Path): UserPrincipal = admins!!
        }
        val view = { Files.getFileAttributeView(created, AclFileAttributeView::class.java) }
        try {
            elevated.prepare()
            val principals = view().acl.map { it.principal() }.distinct()
            assertNotEquals(listOf<UserPrincipal>(admins!!), principals, "private to a group a later run may hold only as deny-only")

            val file = SpoolStore(created).newSpoolFile("get_assets")
            Files.writeString(file, "x")
            assertEquals("x", Files.readString(file), "a run without elevation can still use the spool")
        } finally {
            // Only needed when the regression is present: give the owner access back so cleanup works.
            runCatching {
                if (Files.exists(created)) {
                    view().acl = listOf(
                        AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(created))
                            .setPermissions(EnumSet.allOf(AclEntryPermission::class.java)).build(),
                    )
                }
            }
        }
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    fun `on Windows a directory that already existed keeps its own ACL`() {
        val view = Files.getFileAttributeView(dir, AclFileAttributeView::class.java)
        val before = view.acl
        store.newSpoolFile("get_assets")
        assertEquals(before, view.acl)
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
