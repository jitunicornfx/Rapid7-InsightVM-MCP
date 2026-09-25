package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.testutil.MeteredBody
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for the component that installs code. The security-critical assertions here are the ones
 * that prove a *bad* download is refused: a wrong digest, a non-GitHub host, a wrong artifact, or a
 * size that disagrees with what the release advertised must never reach the installed JAR.
 */
class UpdateInstallerTest {

    private val tempDir: File = createTempDirectory("installer-test").toFile()

    @AfterTest
    fun cleanup() {
        // A test may have taken this process's running marker inside tempDir; Windows will not
        // delete a file that is still open.
        UpdateInstaller.releaseRunningLock()
        tempDir.deleteRecursively()
    }

    /** Build a minimal but genuine JAR carrying the server's entry point. */
    private fun serverJar(file: File, marker: String = "v1"): File {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            zip.putNextEntry(ZipEntry("com/jitunicornfx/insightvm/mcp/MainKt.class"))
            zip.write(marker.toByteArray())
            zip.closeEntry()
        }
        return file
    }

    private fun sha256(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    private fun assetFor(file: File, url: String = "https://github.com/jitunicornfx/Rapid7-InsightVM-MCP/releases/download/v9.9.9/app-all.jar") =
        UpdateChecker.ReleaseAsset(
            name = "rapid7-insightvm-mcp-9.9.9-all.jar",
            downloadUrl = url,
            sha256 = sha256(file),
            sizeBytes = file.length(),
        )

    private fun engineServing(bytes: ByteArray) = MockEngine {
        respond(bytes, HttpStatusCode.OK, headersOf(HttpHeaders.ContentLength, bytes.size.toString()))
    }

    // ---------------------------------------------------------------------
    // Download + verification
    // ---------------------------------------------------------------------

    @Test
    fun `a good download is verified and installed over the target`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val result = UpdateChecker.Result(
            updateAvailable = true, currentVersion = "0.1.6", latestVersion = "9.9.9",
            asset = assetFor(source),
        )

        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), target)

        assertTrue(outcome is UpdateInstaller.Outcome.Installed, "expected an install, got $outcome")
        assertEquals(sha256(source), sha256(target), "target must now be the downloaded bytes")
        assertEquals(emptyList(), tempDir.listFiles()!!.filter { it.name.endsWith(UpdateInstaller.STAGED_SUFFIX) }
            .map { it.name }, "no staging file may be left behind")
    }

    @Test
    fun `a digest mismatch refuses to install and leaves the original intact`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        // Advertise a digest that does not match the bytes actually served.
        val asset = assetFor(source).copy(sha256 = "0".repeat(64))
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = asset)

        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertTrue("SHA-256" in (outcome as UpdateInstaller.Outcome.Failed).reason)
        assertEquals(originalDigest, sha256(target), "a failed verification must not touch the installed JAR")
        assertEquals(emptyList(), tempDir.listFiles()!!.filter { it.name.endsWith(UpdateInstaller.STAGED_SUFFIX) }
            .map { it.name }, "a rejected download leaves no staging file")
    }

    @Test
    fun `bytes that are not a server JAR are refused even with a matching digest`() = runBlocking {
        // Correct hash, wrong artifact: a valid ZIP without the server's entry point.
        val impostor = File(tempDir, "impostor.jar")
        ZipOutputStream(impostor.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("evil/Payload.class")); zip.write("x".toByteArray()); zip.closeEntry()
        }
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(impostor))

        val outcome = UpdateInstaller.install(result, engineServing(impostor.readBytes()), target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertTrue("not a valid server JAR" in (outcome as UpdateInstaller.Outcome.Failed).reason)
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `a download larger than advertised is aborted`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        // Advertise a small size, then serve far more bytes.
        val asset = assetFor(source).copy(sizeBytes = 10)
        val oversized = ByteArray(500_000) { 'A'.code.toByte() }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = asset)

        val outcome = UpdateInstaller.install(result, engineServing(oversized), target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed, "an over-long response must abort")
        assertEquals(originalDigest, sha256(target))
    }

    /**
     * Regression: get() buffered the whole body in memory before returning, so the `written >
     * sizeBytes` stop only ever saw bytes the heap had already accepted — an endless or multi-gigabyte
     * answer from a hop was an OutOfMemoryError inside the server. Streamed, the advertised size is
     * where the transfer stops.
     */
    @Test
    fun `a download far larger than advertised is abandoned as a stream, not buffered`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val body = MeteredBody(totalBytes = 64L * 1024 * 1024)
        val engine = MockEngine { respond(body.channel(), HttpStatusCode.OK) }

        val digest = UpdateInstaller.downloadTo(assetFor(source).copy(sizeBytes = 1000), File(tempDir, "staged.new"), engine)

        assertNull(digest)
        assertTrue(body.wasStreamed(kept = 1000), "${body.produced.get()} of ${body.totalBytes} bytes were pulled for a 1000-byte asset")
    }

    @Test
    fun `a download is never fetched from a non-GitHub host`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val asset = assetFor(source, url = "https://attacker.example/evil-all.jar")
        val engine = engineServing(source.readBytes())
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = asset)

        val outcome = UpdateInstaller.install(result, engine, target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertEquals(0, engine.requestHistory.size, "no request may be sent to a disallowed host")
    }

    @Test
    fun `a redirect to a non-GitHub host is not followed`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val engine = MockEngine { request ->
            if (request.url.host == "github.com") {
                respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "https://attacker.example/evil.jar"))
            } else {
                respond(source.readBytes(), HttpStatusCode.OK)
            }
        }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engine, target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed, "redirect off GitHub must abort the download")
        assertEquals(1, engine.requestHistory.size, "only the original request is made")
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `a redirect to the GitHub CDN is followed and installed`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val engine = MockEngine { request ->
            if (request.url.host == "github.com") {
                respond(
                    "", HttpStatusCode.Found,
                    headersOf(HttpHeaders.Location, "https://objects.githubusercontent.com/release/app-all.jar"),
                )
            } else {
                respond(source.readBytes(), HttpStatusCode.OK)
            }
        }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engine, target)

        assertTrue(outcome is UpdateInstaller.Outcome.Installed, "expected install, got $outcome")
        assertEquals(2, engine.requestHistory.size, "original request plus the CDN hop")
        assertEquals(sha256(source), sha256(target))
    }

    @Test
    fun `install is skipped when the release publishes no verifiable asset`() = runBlocking {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = null)
        val outcome = UpdateInstaller.install(result, engineServing(ByteArray(0)), target)
        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertTrue("no verifiable" in (outcome as UpdateInstaller.Outcome.Failed).reason)
    }

    // ---------------------------------------------------------------------
    // Swap mechanics
    // ---------------------------------------------------------------------

    @Test
    fun `overwriteInPlace replaces contents and removes the staged file`() {
        val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
        val stagedDigest = sha256(staged)

        assertTrue(UpdateInstaller.overwriteInPlace(staged, target, sha256(staged)))

        assertEquals(stagedDigest, sha256(target), "target must carry the new bytes")
        assertFalse(staged.exists(), "staged file consumed")
        assertFalse(File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}").exists(), "backup cleaned up")
    }

    @Test
    fun `installStagedAtShutdown refuses a staged file that is not a server JAR`() {
        val staged = File(tempDir, "staged.jar").apply { writeText("not a jar at all") }
        val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
        val originalDigest = sha256(target)

        assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), originalDigest))
        assertEquals(originalDigest, sha256(target), "a bogus staged file must never be swapped in")
    }

    @Test
    fun `installStagedAtShutdown is a no-op when nothing is staged`() {
        val target = serverJar(File(tempDir, "target.jar"))
        assertFalse(UpdateInstaller.installStagedAtShutdown(File(tempDir, "absent.jar"), target, "0".repeat(64), sha256(target)))
    }

    @Test
    fun `looksLikeServerJar accepts a real server jar and rejects other files`() {
        assertTrue(UpdateInstaller.looksLikeServerJar(serverJar(File(tempDir, "ok.jar"))))
        assertFalse(UpdateInstaller.looksLikeServerJar(File(tempDir, "text.jar").apply { writeText("nope") }))
        assertFalse(UpdateInstaller.looksLikeServerJar(File(tempDir, "missing.jar")))
    }

    @Test
    fun `install is skipped when there is no newer version`() = runBlocking {
        val target = serverJar(File(tempDir, "installed.jar"))
        val result = UpdateChecker.Result(updateAvailable = false, currentVersion = "0.1.6")
        assertEquals(UpdateInstaller.Outcome.Skipped, UpdateInstaller.install(result, engineServing(ByteArray(0)), target))
    }

    @Test
    fun `install fails cleanly when not running from a jar`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))
        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), targetJar = null)
        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertTrue("nothing to replace" in (outcome as UpdateInstaller.Outcome.Failed).reason)
    }

    @Test
    fun `a redirect loop is abandoned rather than followed forever`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        // Always redirect, staying on an allowed host so only the hop limit can stop it.
        val engine = MockEngine {
            respond(
                "", HttpStatusCode.Found,
                headersOf(HttpHeaders.Location, "https://objects.githubusercontent.com/next"),
            )
        }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engine, target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed)
        assertTrue(
            engine.requestHistory.size <= UpdateInstaller.MAX_REDIRECTS + 1,
            "must stop after ${UpdateInstaller.MAX_REDIRECTS} hops, made ${engine.requestHistory.size}",
        )
    }

    @Test
    fun `a redirect without a location header aborts`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val engine = MockEngine { respond("", HttpStatusCode.Found) }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        assertTrue(UpdateInstaller.install(result, engine, target) is UpdateInstaller.Outcome.Failed)
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `an http error response installs nothing`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val engine = MockEngine { respond("not found", HttpStatusCode.NotFound) }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        assertTrue(UpdateInstaller.install(result, engine, target) is UpdateInstaller.Outcome.Failed)
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `a truncated download is refused`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        // Serve fewer bytes than the release advertised.
        val truncated = source.readBytes().copyOfRange(0, source.readBytes().size / 2)
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engineServing(truncated), target)

        assertTrue(outcome is UpdateInstaller.Outcome.Failed, "a short download must not be installed")
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `tryAtomicSwap moves the staged file over the target`() {
        val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
        val stagedDigest = sha256(staged)

        assertTrue(UpdateInstaller.tryAtomicSwap(staged, target))

        assertEquals(stagedDigest, sha256(target))
        assertFalse(staged.exists(), "the staged file is consumed by the move")
    }

    // ---------------------------------------------------------------------
    // Regressions for confirmed review findings
    // ---------------------------------------------------------------------

    @Test
    fun `the backup preserves the ORIGINAL jar, so a failed write can be rolled back`() {
        // Regression: the backup used to copy the *staged* file, so the original was never captured
        // and the "rollback" re-applied the bytes that had just failed.
        val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
        val originalDigest = sha256(target)

        // Force the verification after the write to fail by advertising a digest that cannot match.
        assertFalse(UpdateInstaller.overwriteInPlace(staged, target, "0".repeat(64)))

        assertEquals(originalDigest, sha256(target), "the original JAR must be restored byte-for-byte")
        val backup = File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}")
        assertTrue(backup.exists(), "recovery material must survive a failure")
        assertEquals(originalDigest, sha256(backup), "the backup must hold the ORIGINAL, not the new bytes")
    }

    @Test
    fun `a staged file altered after verification is never installed`() {
        // Regression: the digest used to be computed over the network stream only, so anything that
        // rewrote the staged file between verification and the swap was installed unchecked.
        val staged = serverJar(File(tempDir, "staged.jar"), marker = "VERIFIED")
        val verifiedDigest = sha256(staged)
        val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
        val originalDigest = sha256(target)

        // An attacker (or a second process) swaps the staged file for a different valid server JAR.
        serverJar(staged, marker = "TAMPERED")
        assertTrue(sha256(staged) != verifiedDigest, "precondition: the staged file changed")

        assertFalse(
            UpdateInstaller.installStagedAtShutdown(staged, target, verifiedDigest, originalDigest),
            "a staged file that no longer matches its verified digest must be refused",
        )
        assertEquals(originalDigest, sha256(target), "the running JAR must be untouched")
        assertFalse(staged.exists(), "the tampered staging file is discarded")
    }

    @Test
    fun `overwriteInPlace verifies what it actually wrote`() {
        val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")

        assertTrue(UpdateInstaller.overwriteInPlace(staged, target, sha256(staged)))
        assertFalse(
            File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}").exists(),
            "a verified success cleans up its backup",
        )
    }

    @Test
    fun `an install is refused while another process holds the lock`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        // Hold the cross-process install lock, exactly as a second server process would.
        val held = UpdateInstaller.withInstallLock(target) {
            runBlocking { UpdateInstaller.install(result, engineServing(source.readBytes()), target) }
        }

        val outcome = assertIs<UpdateInstaller.LockResult.Acquired<UpdateInstaller.Outcome>>(held).value
        assertIs<UpdateInstaller.Outcome.Failed>(outcome, "a contended install must not proceed")
        assertTrue("another process" in outcome.reason)
        assertEquals(originalDigest, sha256(target), "the JAR is untouched while the lock is held")
    }

    /**
     * The sidecar is never deleted, by anyone. It carries an OS lock that the kernel releases when
     * the holder exits, so a leftover file blocks nothing — while unlinking a held one lets the next
     * arrival lock a fresh file at the same path and install concurrently.
     */
    @Test
    fun `the lock sidecar is never deleted and does not block a later acquisition`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)

        assertEquals(
            UpdateInstaller.LockResult.Acquired(42),
            UpdateInstaller.withInstallLock(target) { assertTrue(lockFile.isFile); 42 },
        )
        assertTrue(lockFile.isFile, "the sidecar outlives its holder")
        assertEquals(0, lockFile.length(), "it is a pure lock carrier, never written to")

        // A leftover sidecar must not stop the next install from acquiring.
        assertEquals(UpdateInstaller.LockResult.Acquired(7), UpdateInstaller.withInstallLock(target) { 7 })
        assertTrue(lockFile.isFile)

        // Mutual exclusion still holds while contended.
        UpdateInstaller.withInstallLock(target) {
            assertEquals(UpdateInstaller.LockResult.Contended, UpdateInstaller.withInstallLock(target) { "inner" })
            assertTrue(lockFile.isFile, "a contender must not delete a lock it does not hold")
        }
        assertTrue(lockFile.isFile)
    }

    /**
     * Contention, a broken directory and a failing block are different things to an operator, and
     * only the first may be reported as "another process is installing".
     */
    @Test
    fun `the install lock tells contention, an unusable sidecar and a failing block apart`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)

        val failing = UpdateInstaller.withInstallLock(target) { error("boom at ${tempDir.absolutePath}") }
        assertEquals(
            UpdateInstaller.LockResult.Unavailable("unexpected IllegalStateException while holding ${lockFile.name}"),
            failing,
            "the class is reported, never the message, which can carry a path",
        )
        assertEquals(UpdateInstaller.LockResult.Acquired(1), UpdateInstaller.withInstallLock(target) { 1 }, "and the lock was released")

        assertTrue(lockFile.delete() && lockFile.mkdir())
        val unusable = assertIs<UpdateInstaller.LockResult.Unavailable>(UpdateInstaller.withInstallLock(target) { 1 })
        assertTrue(unusable.reason.startsWith("cannot create ${lockFile.name}: "), unusable.reason)
        assertTrue(unusable.reason.endsWith("is the install directory writable?"), unusable.reason)
        assertFalse(tempDir.absolutePath in unusable.reason)
    }

    /**
     * Regression: the sweep used to delete the sidecar exempt from the age check and without any
     * holder test, contradicting its own documentation. Windows refuses the delete while a handle is
     * open, so the damage was POSIX-only and invisible here — the fix is to not sweep it at all,
     * which is platform-independent and testable anywhere.
     */
    @Test
    fun `cleanupStaleArtifacts never removes the lock sidecar, held or not`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)
        val now = System.currentTimeMillis()

        // An ancient, entirely unheld sidecar: still not the sweep's business.
        lockFile.writeText("")
        assertTrue(lockFile.setLastModified(now - 30L * 24 * 60 * 60 * 1000))
        assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(target, now = now))
        assertTrue(lockFile.isFile, "an unheld sidecar is harmless and must survive")

        // And one that is actively held must survive a concurrent sweep, with the lock still valid.
        UpdateInstaller.withInstallLock(target) {
            assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(target, now = now))
            assertTrue(lockFile.isFile, "sweeping a held lock would break mutual exclusion")
            assertEquals(
                UpdateInstaller.LockResult.Contended,
                UpdateInstaller.withInstallLock(target) { "inner" },
                "the lock still excludes",
            )
        }
    }

    @Test
    fun `cleanupStaleArtifacts removes old staging and backup files but nothing else`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val hour = UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS
        val now = System.currentTimeMillis()
        fun make(name: String, ageMillis: Long): File = File(tempDir, name).apply {
            writeText("x")
            assertTrue(setLastModified(now - ageMillis))
        }
        val oldStaged = make("installed.jar.1234.new", hour + 1)
        val oldStaged2 = make("installed.jar.5678.new", 2 * hour)
        val freshStaged = make("installed.jar.9999.new", 1_000)
        val oldBackup = make("installed.jar.bak", hour + 1)
        val lock = make("installed.jar.update.lock", 0)
        val otherServer = make("other-server.jar.1111.new", 3 * hour)
        val otherLock = make("other-server.jar.update.lock", 0)
        val unrelated = make("installed.jar.notes.txt", 3 * hour)

        val removed = UpdateInstaller.cleanupStaleArtifacts(target, now = now)

        assertEquals(setOf(oldStaged.name, oldStaged2.name, oldBackup.name), removed.toSet())
        assertFalse(oldStaged.exists()); assertFalse(oldStaged2.exists()); assertFalse(oldBackup.exists())
        assertTrue(lock.isFile, "the lock sidecar is never swept")
        assertTrue(freshStaged.exists(), "a recent staging file may belong to a running sibling")
        assertTrue(otherServer.exists()); assertTrue(otherLock.exists()); assertTrue(unrelated.exists())
        assertTrue(target.isFile)

        // Second pass: nothing left to do; a missing parent directory is handled.
        assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(target, now = now))
        assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(File(tempDir, "missing/dir/x.jar")))
        assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(File("bare.jar")))
    }

    @Test
    fun `install sweeps stale staging files before downloading`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val stale = File(tempDir, "installed.jar.0000.new").apply {
            writeText("old")
            assertTrue(setLastModified(System.currentTimeMillis() - 2 * UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS))
        }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))
        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), target)
        assertTrue(outcome is UpdateInstaller.Outcome.Installed || outcome is UpdateInstaller.Outcome.Staged, outcome.toString())
        assertFalse(stale.exists(), "stale staging file swept")
        assertTrue(
            File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).isFile,
            "the lock sidecar survives the install; deleting it is what would break mutual exclusion",
        )
    }

    @Test
    fun `each install stages to its own file rather than a shared predictable path`() = runBlocking {
        // Regression: a fixed "<jar>.new" path let concurrent processes clobber each other's download.
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        // A leftover file at the old predictable path must be neither adopted nor deleted.
        val squatter = File(tempDir, "installed.jar${UpdateInstaller.STAGED_SUFFIX}")
        squatter.writeText("someone else's file")
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        UpdateInstaller.install(result, engineServing(source.readBytes()), target)

        assertTrue(squatter.exists(), "another process's file must not be deleted")
        assertEquals("someone else's file", squatter.readText(), "nor overwritten")
    }

    @Test
    fun `runningJar returns null under the test runner, disabling installation`() {
        // Tests run from a classes directory, not a JAR — there is no single file to replace.
        assertNull(UpdateInstaller.runningJar())
    }

    // ---------------------------------------------------------------------
    // A staged update waits for its process to exit, possibly for days
    // ---------------------------------------------------------------------

    /** Poll [condition] until it holds or [timeoutMillis] passes; for the heartbeat's own thread. */
    private fun awaitTrue(timeoutMillis: Long = 5_000, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    /**
     * Regression: the shutdown swap took only the install lock, which serialises installers but not
     * running servers. Stdio deployment runs one JVM per client from one JAR, and each loads classes
     * from it lazily, so rewriting the bytes as one exits broke the others' next first-time class load
     * with an Error no tool handler catches. Every server now holds a shared lock on `<jar>.running`
     * for its lifetime, and the rewrite needs that lock exclusively.
     */
    @Test
    fun `the shutdown install does not rewrite a JAR another server is still running from`() {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
        val stagedBytes = staged.readBytes()
        val newDigest = sha256(staged)

        // A sibling server's lifetime marker. Within one JVM the overlapping lock attempt throws
        // OverlappingFileLockException rather than returning null; the installer treats both alike.
        RandomAccessFile(File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX), "rw").use { sibling ->
            sibling.channel.lock(0, Long.MAX_VALUE, true)
            assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest))
            assertEquals(originalDigest, sha256(target), "a JAR another server is running from must not be rewritten")
            assertFalse(staged.exists(), "the stage is discarded; a later start re-stages the update")
        }

        // Once the sibling has gone, the same update installs.
        staged.writeBytes(stagedBytes)
        assertTrue(UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest))
        assertEquals(newDigest, sha256(target))
    }

    @Test
    fun `a running marker excludes the rewrite until it is released, and is never deleted`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val marker = File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX)

        assertTrue(UpdateInstaller.holdRunningLock(target))
        assertEquals(UpdateInstaller.LockResult.Contended, UpdateInstaller.withSoleUse(target) { "rewrite" })

        UpdateInstaller.releaseRunningLock()
        assertEquals(UpdateInstaller.LockResult.Acquired("rewrite"), UpdateInstaller.withSoleUse(target) { "rewrite" })
        assertTrue(marker.isFile, "the marker is a 0-byte lock carrier and outlives every holder")
        assertEquals(0, marker.length())
        assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(target, maxAgeMillis = 0))
        assertTrue(marker.isFile, "and it is never swept")

        // A marker that cannot be taken costs only the protection; it never throws.
        RandomAccessFile(marker, "rw").use { other ->
            other.channel.lock(0, Long.MAX_VALUE, true)
            assertFalse(UpdateInstaller.holdRunningLock(target), "an overlapping lock in this JVM is not ours")
        }
        assertTrue(marker.delete() && marker.mkdir())
        assertFalse(UpdateInstaller.holdRunningLock(target))
        assertIs<UpdateInstaller.LockResult.Unavailable>(UpdateInstaller.withSoleUse(target) { "rewrite" })
    }

    @Test
    fun `the shutdown install refuses when it cannot tell whether other servers are running`() {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
        assertTrue(File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX).mkdir())

        assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), originalDigest))
        assertEquals(originalDigest, sha256(target))
    }

    @Test
    fun `the shutdown install stands aside while the install lock is held or unusable`() {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
        val newDigest = sha256(staged)

        UpdateInstaller.withInstallLock(target) {
            assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest))
        }
        assertEquals(originalDigest, sha256(target), "never while another process is installing")

        assertTrue(File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).let { it.delete() && it.mkdir() })
        assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest))
        assertEquals(originalDigest, sha256(target), "nor without the lock at all")
    }

    @Test
    fun `an install is refused when the installed JAR cannot be read to record what it replaces`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        // Not a readable file: there is no digest to hold a later shutdown swap to.
        val target = File(tempDir, "installed.jar").apply { assertTrue(mkdir()) }
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))
        val engine = engineServing(source.readBytes())

        val outcome = UpdateInstaller.install(result, engine, target)

        assertIs<UpdateInstaller.Outcome.Failed>(outcome)
        assertTrue("could not read installed.jar" in outcome.reason, outcome.reason)
        assertEquals(0, engine.requestHistory.size, "nothing is downloaded that could never be applied")
    }

    @Test
    fun `a server's own running marker never blocks its own shutdown install`() {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")

        assertTrue(UpdateInstaller.holdRunningLock(target), "the marker is taken")
        assertTrue(UpdateInstaller.holdRunningLock(target), "taking it again in the same process is a no-op")

        assertTrue(UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), sha256(target)))
    }

    /**
     * Regression: the shutdown swap re-verified the staged file but never the target. A stage waits
     * for its process to exit, and if a sibling installed something NEWER meanwhile, this older copy
     * was written over it: a silent downgrade, possibly past a security fix.
     */
    @Test
    fun `a staged update is discarded when the installed JAR changed after it was staged`() {
        val target = serverJar(File(tempDir, "installed.jar"), marker = "0.2.1")
        val whenStaged = sha256(target)
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "0.2.2")
        // Meanwhile another server installed a newer release over the same path.
        serverJar(File(tempDir, "newer.jar"), marker = "0.2.3").copyTo(target, overwrite = true)
        val replacement = sha256(target)

        assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), whenStaged))
        assertEquals(replacement, sha256(target), "the newer JAR must not be overwritten by an older stage")
        assertFalse(staged.exists(), "the stale stage is discarded")
    }

    /**
     * Regression: withInstallLock mapped every failure to null, which install() reported as "another
     * process is already installing an update" — on every start, for an install directory that
     * could never work.
     */
    @Test
    fun `an unusable install directory is reported as such, not as another process installing`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"))
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        // A directory squats on the sidecar's name, so it cannot be opened as a file.
        assertTrue(File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).mkdir())
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), target)

        assertIs<UpdateInstaller.Outcome.Failed>(outcome)
        assertTrue("cannot create" in outcome.reason, outcome.reason)
        assertFalse("another process" in outcome.reason, outcome.reason)
        assertFalse(tempDir.absolutePath in outcome.reason, "a reason sent to the client carries no path")
        assertEquals(originalDigest, sha256(target))
    }

    /**
     * Regression: a stage stays pending until its process exits — for an MCP server, days — and
     * nothing kept it looking alive. A sibling started more than [UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS]
     * later swept it as abandoned, and the owner went on reporting "restart to apply" for an update
     * that was gone.
     */
    @Test
    fun `a pending stage kept fresh by its live owner survives a sibling's startup sweep`() {
        val target = serverJar(File(tempDir, "installed.jar"))
        val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
        val overADay = UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS + 60_000
        // Staged over a day ago by a server that is still running.
        assertTrue(staged.setLastModified(System.currentTimeMillis() - overADay))

        UpdateInstaller.keepStagedFresh(staged, intervalMillis = 10) { }.use {
            assertTrue(
                awaitTrue { System.currentTimeMillis() - staged.lastModified() < UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS },
                "the heartbeat must re-stamp the stage",
            )
            assertEquals(emptyList(), UpdateInstaller.cleanupStaleArtifacts(target), "a live stage is not abandoned")
            assertTrue(staged.isFile)
            val heartbeats = Thread.getAllStackTraces().keys.filter { it.name == UpdateInstaller.HEARTBEAT_THREAD_NAME }
            assertTrue(heartbeats.isNotEmpty() && heartbeats.all { it.isDaemon }, "the heartbeat must never keep the JVM alive")
        }

        // Closed, it stops: a stage whose owner is gone still ages out, and nothing pins it any more.
        assertTrue(staged.setLastModified(System.currentTimeMillis() - overADay))
        Thread.sleep(100)
        assertEquals(listOf(staged.name), UpdateInstaller.cleanupStaleArtifacts(target))
    }

    @Test
    fun `the heartbeat reports a stage that vanished, exactly once`() {
        val staged = serverJar(File(tempDir, "installed.jar.1.new"))
        val reports = AtomicInteger()

        UpdateInstaller.keepStagedFresh(staged, intervalMillis = 10, pin = false) { reports.incrementAndGet() }.use {
            assertTrue(staged.delete())
            assertTrue(awaitTrue { reports.get() > 0 }, "a lost stage must be reported")
            Thread.sleep(100) // ten more intervals' worth
            assertEquals(1, reports.get(), "reported once, not on every tick")
        }
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    fun `on Windows the keep-alive pin refuses a sibling's delete of the stage`() {
        val staged = serverJar(File(tempDir, "installed.jar.1.new"))

        UpdateInstaller.keepStagedFresh(staged, intervalMillis = 60_000) { }.use {
            assertFalse(staged.delete(), "the JDK opens without FILE_SHARE_DELETE, so another delete is refused")
        }
        assertTrue(staged.delete(), "closing the keep-alive releases the pin, or the shutdown swap could not delete it either")
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    fun `a staged install records the JAR it will replace`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val originalDigest = sha256(target)
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        // Hold the target open as a running JVM does; Windows then refuses to move anything over it.
        val outcome = target.inputStream().use { UpdateInstaller.install(result, engineServing(source.readBytes()), target) }

        assertIs<UpdateInstaller.Outcome.Staged>(outcome)
        assertEquals(originalDigest, outcome.targetSha256, "the shutdown swap compares against this")
        assertEquals(originalDigest, sha256(target))
    }

    /**
     * Regression: createTempFile makes the stage rw------- on POSIX, and the atomic move carried that
     * mode onto the installed JAR, so every other account using a shared install got "Unable to
     * access jarfile". POSIX only, so it is skipped on Windows; run the suite on Linux or macOS to exercise it.
     */
    @Test
    @EnabledOnOs(OS.LINUX, OS.MAC)
    fun `an atomic install keeps the installed JAR's permissions`() = runBlocking {
        val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
        val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
        val shared = PosixFilePermissions.fromString("rw-r--r--")
        Files.setPosixFilePermissions(target.toPath(), shared)
        val result = UpdateChecker.Result(true, "0.1.6", "9.9.9", asset = assetFor(source))

        val outcome = UpdateInstaller.install(result, engineServing(source.readBytes()), target)

        assertIs<UpdateInstaller.Outcome.Installed>(outcome)
        assertEquals(shared, Files.getPosixFilePermissions(target.toPath()), "the JAR keeps its mode across the swap")
    }
}
