package com.jitunicornfx.insightvm.mcp

import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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

        assertFalse(UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged)))
        assertEquals(originalDigest, sha256(target), "a bogus staged file must never be swapped in")
    }

    @Test
    fun `installStagedAtShutdown is a no-op when nothing is staged`() {
        val target = serverJar(File(tempDir, "target.jar"))
        assertFalse(UpdateInstaller.installStagedAtShutdown(File(tempDir, "absent.jar"), target, "0".repeat(64)))
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
            UpdateInstaller.installStagedAtShutdown(staged, target, verifiedDigest),
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
        val outcome = UpdateInstaller.withInstallLock(target) {
            runBlocking { UpdateInstaller.install(result, engineServing(source.readBytes()), target) }
        }

        assertTrue(outcome is UpdateInstaller.Outcome.Failed, "a contended install must not proceed")
        assertTrue("another process" in (outcome as UpdateInstaller.Outcome.Failed).reason)
        assertEquals(originalDigest, sha256(target), "the JAR is untouched while the lock is held")
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
}
