package com.jitunicornfx.insightvm.mcp

import io.ktor.client.*
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.core.remaining
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Downloads a newer release and installs it over the JAR this server is running from.
 *
 * ## Why this is written defensively
 *
 * This is the one component that installs code. Everything it fetches is remote and therefore
 * attacker-influenceable, so the download is treated as hostile until proven otherwise:
 *
 *  - **The SHA-256 digest published by the GitHub API is mandatory and verified before anything is
 *    installed.** A byte that does not hash to the expected digest is never swapped in.
 *  - **Redirects are followed manually**, one hop at a time, and every hop must be HTTPS on a
 *    GitHub-owned host ([UpdateChecker.isAllowedDownloadUrl]). GitHub serves release binaries via a
 *    redirect to its CDN, so redirects cannot simply be disabled — but they must not be able to
 *    steer the download to an arbitrary host.
 *  - **No credentials are ever sent.** The InsightVM API key must never leave Rapid7 hosts, and the
 *    releases endpoint is public, so this uses its own unauthenticated client.
 *  - **The payload must be a real JAR** containing this server's entry point before it replaces
 *    anything, so a valid-hash-but-wrong-artifact swap cannot brick the install.
 *  - **Nothing throws.** Every failure degrades to an [Outcome] describing what happened.
 *
 * ## Residual risk (deliberately documented, not solved here)
 *
 * The digest is fetched from the same GitHub API response that advertises the download. That
 * defends against a corrupted or tampered *download* (CDN compromise, an interception of the asset
 * fetch, truncation), but **not** against an attacker who controls the GitHub release itself — a
 * repository or account compromise would serve a matching digest for malicious bytes. Defending
 * against that requires signature verification against a pinned public key, which this project does
 * not yet publish. Operators who cannot accept that residual risk should disable automatic
 * installation ([Config.ENV_DISABLE_AUTO_UPDATE] or `--no-auto-update`) and update manually.
 */
object UpdateInstaller {

    /** Generous ceiling for the whole download; a ~19MB artifact over a slow link still fits. */
    const val DOWNLOAD_TIMEOUT_MS = 300_000L

    /** Maximum redirect hops followed while resolving a release asset to its CDN location. */
    const val MAX_REDIRECTS = 5

    /** Suffix for the staged download sitting beside the installed JAR. */
    const val STAGED_SUFFIX = ".new"

    /** Suffix for the pre-swap backup of the ORIGINAL JAR, kept so a failed write can be undone. */
    const val BACKUP_SUFFIX = ".bak"

    /** Sidecar used to serialise installation across processes launched from the same JAR. */
    const val LOCK_SUFFIX = ".update.lock"

    /**
     * Age after which a leftover staging (`.new`) or backup (`.bak`) file beside the JAR is considered
     * abandoned. A staged update is normally applied when the process that downloaded it exits; if
     * that process was killed, the file stays behind forever — and every later download creates a
     * fresh one, at ~20 MB each, which is what makes sweeping worth doing at all.
     *
     * The window cannot be derived from the download, only from the SESSION: a staged file stays
     * pending until its process exits, and an MCP server can run for days. Because stdio deployment
     * starts one JVM per client from the same JAR, a sibling starting later will sweep a pending
     * stage whose owner is still alive, and that owner's shutdown hook then finds nothing to install.
     * That costs a repeated download rather than correctness — the next check re-stages it — so this
     * is a deliberate trade rather than a bound that can be made exact. A day is long enough that a
     * normally-restarted server keeps its pending stage, and short enough that a killed one does not
     * leave 20 MB sitting there indefinitely. [installStagedAtShutdown] says so out loud when it hits
     * the losing case, so a user seeing repeated downloads can raise this rather than guess.
     */
    const val STALE_ARTIFACT_AGE_MILLIS = 24L * 60 * 60 * 1000

    /** What happened, for logging and for the notification sent to the MCP client. */
    sealed interface Outcome {
        /** The new JAR is installed at the original path; the new code activates on restart. */
        data class Installed(val version: String, val path: String) : Outcome

        /**
         * The new JAR was downloaded and verified, but the running JVM holds the target file such
         * that it cannot be replaced yet. It is staged at [stagedPath] and will be swapped in when
         * this process exits — at which point [sha256] is re-checked against the file on disk, so a
         * staged file that changed in the meantime is never installed.
         */
        data class Staged(val version: String, val stagedPath: String, val sha256: String) : Outcome

        /** Nothing was installed. [reason] is server-authored text, never remote content. */
        data class Failed(val reason: String) : Outcome

        /** Automatic installation is switched off, or there is nothing to install. */
        data object Skipped : Outcome
    }

    /** SHA-256 of a file **as it exists on disk**, or null if it cannot be read. */
    internal fun sha256Of(file: File): String? = runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    /**
     * Run [block] while holding an exclusive lock on a sidecar beside [target], or return null if
     * another process already holds it.
     *
     * The staging file and the target JAR are machine-wide resources: the usual stdio deployment
     * starts one JVM per MCP client from the same JAR path, so an in-process flag cannot serialise
     * them. Everything from download through swap runs inside this lock.
     */
    internal fun <T> withInstallLock(target: File, block: () -> T): T? {
        val lockFile = File(target.parentFile, target.name + LOCK_SUFFIX)
        return runCatching {
            RandomAccessFile(lockFile, "rw").use { raf ->
                raf.channel.use { channel ->
                    val lock = runCatching { channel.tryLock() }.getOrNull() ?: return null
                    lock.use { block() }
                }
            }
        }.getOrNull()
        // The sidecar is deliberately NEVER deleted — not here, not by cleanupStaleArtifacts.
        //
        // It is a 0-byte file whose only job is to carry an OS lock, and the OS releases that lock
        // when the holder exits, abnormal termination included. A leftover sidecar therefore blocks
        // nothing: the next process reopens it and acquires it immediately. Deleting it buys no
        // disk and no correctness, and costs both — on POSIX, unlink() ignores open handles and
        // advisory locks, so removing it while anyone holds it lets the next arrival create a fresh
        // file at the same path and lock that instead, and two installs then run concurrently.
        // Windows refuses the delete while a handle is open, which is the only reason the previous
        // "holder deletes on release" behaviour was not actively breaking mutual exclusion there.
    }

    /**
     * Delete abandoned update artifacts beside [target] — staging files (`<jar>.*.new`) and backups
     * (`<jar>.bak`) older than [maxAgeMillis]. Only files whose name starts with the JAR's own name
     * are considered, so neighbouring servers' files are never touched. Returns what was removed.
     *
     * The `.update.lock` sidecar is deliberately NOT swept: it is 0 bytes, it blocks nothing once
     * its holder exits, and unlinking one that is still held breaks the mutual exclusion it exists
     * to provide. See [withInstallLock].
     */
    fun cleanupStaleArtifacts(
        target: File,
        maxAgeMillis: Long = STALE_ARTIFACT_AGE_MILLIS,
        now: Long = System.currentTimeMillis(),
    ): List<String> {
        val dir = target.parentFile ?: return emptyList()
        val prefix = target.name + "."
        val candidates = dir.listFiles() ?: return emptyList()
        val removed = mutableListOf<String>()
        for (file in candidates) {
            if (!file.isFile || file == target || !file.name.startsWith(prefix)) continue
            val isStaged = file.name.endsWith(STAGED_SUFFIX)
            val isBackup = file.name == target.name + BACKUP_SUFFIX
            if (!isStaged && !isBackup) continue
            if (now - file.lastModified() < maxAgeMillis) continue
            if (runCatching { file.delete() }.getOrDefault(false)) removed += file.name
        }
        return removed
    }

    /**
     * Locate the JAR this JVM is running from, or null when not running from a JAR (e.g. tests and
     * `gradle run`, where the code source is a directory). A null result disables installation:
     * there is no single file to replace.
     */
    internal fun runningJar(): File? {
        val source = runCatching {
            UpdateInstaller::class.java.protectionDomain?.codeSource?.location?.toURI()
        }.getOrNull() ?: return null
        val file = runCatching { File(source) }.getOrNull() ?: return null
        return file.takeIf { it.isFile && it.name.endsWith(".jar", ignoreCase = true) }
    }

    /** Hex-encode a digest for comparison against GitHub's `sha256:` value. */
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /**
     * Verify [file] is a genuine JAR that carries this server's entry point.
     *
     * A correct hash only proves the bytes match what GitHub advertised; it does not prove they are
     * *this program*. Checking for the main class stops a well-formed but wrong artifact from being
     * installed and leaving an unstartable server behind.
     */
    internal fun looksLikeServerJar(file: File): Boolean = runCatching {
        ZipFile(file).use { zip ->
            zip.getEntry("com/jitunicornfx/insightvm/mcp/MainKt.class") != null
        }
    }.getOrDefault(false)

    /**
     * Download [asset], following GitHub's CDN redirect by hand with a host allow-list at every hop,
     * and write it to [destination]. Returns the SHA-256 of the bytes actually written, or null on
     * any failure. The stream is hashed and size-capped as it is written, so an over-long or
     * truncated response never reaches the verification step with a passing digest.
     */
    internal suspend fun downloadTo(
        asset: UpdateChecker.ReleaseAsset,
        destination: File,
        engine: HttpClientEngine? = null,
    ): String? = runCatching {
        val http = if (engine != null) HttpClient(engine) { configure() } else HttpClient(OkHttp) { configure() }
        http.use { client ->
            var url = asset.downloadUrl
            var hops = 0
            while (true) {
                if (!UpdateChecker.isAllowedDownloadUrl(url)) return null
                val response = client.get(url) {
                    header(HttpHeaders.Accept, "application/octet-stream")
                    header(HttpHeaders.UserAgent, "$SERVER_NAME/$SERVER_VERSION")
                }
                if (response.status.value in 300..399) {
                    // Follow the CDN hop ourselves so the allow-list is re-checked for the target.
                    val location = response.headers[HttpHeaders.Location] ?: return null
                    if (++hops > MAX_REDIRECTS) return null
                    url = location
                    continue
                }
                if (response.status.value !in 200..299) return null
                val declared = response.contentLength()
                if (declared != null && declared > asset.sizeBytes) return null

                val digest = MessageDigest.getInstance("SHA-256")
                var written = 0L
                val channel = response.bodyAsChannel()
                destination.outputStream().buffered().use { out ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = channel.readAvailable(buffer, 0, buffer.size)
                        if (read == -1) break
                        if (read == 0) continue
                        written += read
                        // Hard-stop a response that exceeds the advertised size rather than
                        // buffering an unbounded stream to disk.
                        if (written > asset.sizeBytes) return null
                        digest.update(buffer, 0, read)
                        out.write(buffer, 0, read)
                    }
                }
                if (written != asset.sizeBytes) return null
                return digest.digest().toHex()
            }
            @Suppress("UNREACHABLE_CODE") null
        }
    }.getOrNull()

    /**
     * Replace [target] with [staged].
     *
     * Prefers an atomic move, which on POSIX swaps the directory entry while the running JVM keeps
     * reading the old inode through its open handle — the safe case. Windows refuses to rename or
     * move over a JAR the current JVM is running from (measured), so there the move fails and the
     * caller falls back to swapping at shutdown.
     */
    internal fun tryAtomicSwap(staged: File, target: File): Boolean = runCatching {
        Files.move(staged.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        true
    }.getOrElse { error ->
        if (error is AtomicMoveNotSupportedException) {
            runCatching {
                Files.move(staged.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
                true
            }.getOrDefault(false)
        } else {
            false
        }
    }

    /**
     * Overwrite [target]'s contents in place from [staged], keeping a backup so a partial write can
     * be rolled back.
     *
     * This is the Windows path and is intended for **JVM shutdown**, once class loading has settled:
     * rewriting the bytes of a JAR a running JVM has open can otherwise break lazily-loaded classes.
     * Returns true only when the new contents are fully in place.
     */
    internal fun overwriteInPlace(staged: File, target: File, expectedSha256: String): Boolean {
        val backup = File(target.parentFile, target.name + BACKUP_SUFFIX)

        // Capture the ORIGINAL before touching it — this is the only copy of the currently working
        // server, and it is what a failed write must be rolled back to.
        val backedUp = runCatching { target.copyTo(backup, overwrite = true) }.isSuccess &&
            backup.length() == target.length()
        if (!backedUp) {
            System.err.println("[insightvm-mcp] Could not back up ${target.name}; refusing to overwrite it.")
            return false
        }

        /** Stream [source] over [destination]'s existing path (truncating open, never unlink). */
        fun writeOver(source: File, destination: File): Boolean = runCatching {
            source.inputStream().buffered().use { input ->
                // Truncating open() on the existing path is permitted on Windows even while the JVM
                // holds the JAR, unlike rename/move — and it keeps the path's identity intact.
                destination.outputStream().buffered().use { output -> input.copyTo(output) }
            }
            true
        }.getOrDefault(false)

        val wrote = writeOver(staged, target)
        // Trust nothing: confirm the bytes now on disk are exactly what was verified.
        if (wrote && sha256Of(target) == expectedSha256) {
            runCatching { backup.delete() }
            runCatching { staged.delete() }
            return true
        }

        // The write failed or produced the wrong bytes. Restore the original in place, and KEEP the
        // backup and the staged file either way so an operator always has something to recover from.
        val restored = writeOver(backup, target) && sha256Of(target) == sha256Of(backup)
        System.err.println(
            if (restored) {
                "[insightvm-mcp] Update write failed; restored the previous ${target.name}. " +
                    "A copy remains at ${backup.absolutePath}."
            } else {
                "[insightvm-mcp] Update write failed AND the original could not be restored. " +
                    "Recover ${target.absolutePath} from ${backup.absolutePath} before restarting."
            },
        )
        return false
    }

    /**
     * Download, verify and install [result]'s asset over the running JAR.
     *
     * Returns an [Outcome] describing what happened; never throws. When the target cannot be
     * replaced while running (Windows), the verified download is left staged and
     * [installStagedAtShutdown] completes the swap as the JVM exits.
     */
    suspend fun install(
        result: UpdateChecker.Result,
        engine: HttpClientEngine? = null,
        targetJar: File? = runningJar(),
    ): Outcome = withContext(Dispatchers.IO) {
        val version = result.latestVersion ?: return@withContext Outcome.Skipped
        val asset = result.asset
            ?: return@withContext Outcome.Failed("release $version publishes no verifiable .jar asset")
        val target = targetJar
            ?: return@withContext Outcome.Failed("not running from a .jar, so there is nothing to replace")

        // Serialise the whole download-verify-swap against other processes started from this JAR.
        val outcome = withInstallLock(target) {
            cleanupStaleArtifacts(target)
            // A unique staging file, created exclusively: two processes can never share one, and a
            // pre-existing file left by someone else is never adopted or deleted.
            val stagedPath = runCatching {
                Files.createTempFile(target.parentFile.toPath(), "${target.name}.", STAGED_SUFFIX)
            }.getOrNull() ?: return@withInstallLock Outcome.Failed("could not create a staging file next to ${target.name}")
            val staged = stagedPath.toFile()

            fun fail(reason: String): Outcome {
                runCatching { staged.delete() }
                return Outcome.Failed(reason)
            }

            val streamedDigest = runBlocking { downloadTo(asset, staged, engine) }
                ?: return@withInstallLock fail("download of $version failed or exceeded its advertised size")

            // Two checks, deliberately: the streamed digest catches a tampered/truncated transfer,
            // and re-hashing the file catches anything that touched it after it was written. The
            // value that authorises the swap is always computed from the bytes on disk.
            if (!streamedDigest.equals(asset.sha256, ignoreCase = true)) {
                return@withInstallLock fail("SHA-256 mismatch for $version — refusing to install")
            }
            val onDisk = sha256Of(staged)
            if (onDisk == null || !onDisk.equals(asset.sha256, ignoreCase = true)) {
                return@withInstallLock fail("staged $version does not match its published SHA-256 — refusing to install")
            }
            if (!looksLikeServerJar(staged)) {
                return@withInstallLock fail("downloaded $version is not a valid server JAR — refusing to install")
            }

            if (tryAtomicSwap(staged, target)) {
                Outcome.Installed(version, target.absolutePath)
            } else {
                Outcome.Staged(version, staged.absolutePath, asset.sha256)
            }
        }
        outcome ?: Outcome.Failed("another process is already installing an update")
    }

    /**
     * Complete a [Outcome.Staged] install as the JVM exits, when overwriting the JAR in place is
     * safe because class loading is finished. Best-effort and silent on failure: the staged file
     * simply remains for the next start.
     */
    fun installStagedAtShutdown(staged: File, target: File, expectedSha256: String): Boolean {
        if (!staged.isFile) {
            // Almost always means a sibling process swept it as stale while this one kept running.
            // Silence here looks like "the update just never happened"; name it so the cause is
            // visible and STALE_ARTIFACT_AGE_MILLIS is the obvious dial.
            System.err.println(
                "[insightvm-mcp] Staged update ${staged.name} is gone; nothing was installed. " +
                    "It was most likely swept as stale by another server process started from this JAR. " +
                    "The update will be downloaded again on the next check.",
            )
            return false
        }
        // The staged file has been sitting on disk for the whole session, so re-verify it against
        // the digest that authorised it. looksLikeServerJar is an anti-brick sanity check, never the
        // integrity gate — any ZIP carrying the right entry name would satisfy it.
        val onDisk = sha256Of(staged)
        if (onDisk == null || !onDisk.equals(expectedSha256, ignoreCase = true)) {
            System.err.println("[insightvm-mcp] Staged update no longer matches its verified digest; discarding it.")
            runCatching { staged.delete() }
            return false
        }
        if (!looksLikeServerJar(staged)) {
            runCatching { staged.delete() }
            return false
        }
        // Only swap when no other process from this JAR is mid-install.
        return withInstallLock(target) { overwriteInPlace(staged, target, expectedSha256) } ?: false
    }

    private fun HttpClientConfig<*>.configure() {
        expectSuccess = false
        // Redirects are resolved manually so the host allow-list applies to every hop.
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = DOWNLOAD_TIMEOUT_MS
            connectTimeoutMillis = UpdateChecker.TIMEOUT_MS
            socketTimeoutMillis = DOWNLOAD_TIMEOUT_MS
        }
    }
}
