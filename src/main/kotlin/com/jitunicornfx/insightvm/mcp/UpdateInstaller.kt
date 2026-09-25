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
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFileAttributeView
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
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

    /** Sidecar on which every server started from a JAR holds a SHARED lock for as long as it runs. */
    const val RUNNING_SUFFIX = ".running"

    /**
     * Age after which a leftover staging (`.new`) or backup (`.bak`) file beside the JAR is considered
     * abandoned. A staged update is normally applied when the process that downloaded it exits; if
     * that process was killed, the file stays behind forever — and every later download creates a
     * fresh one, at ~20 MB each, which is what makes sweeping worth doing at all.
     *
     * Age alone cannot tell "abandoned" from "pending": a staged file stays pending until its process
     * exits, an MCP server can run for days, and stdio deployment starts one JVM per client from the
     * same JAR, each sweeping at startup. So a live owner keeps its stage young with
     * [keepStagedFresh], which re-stamps it well inside this window; only a stage whose owner has gone
     * ages past it. A day is short enough that a killed server does not leave 20 MB sitting there
     * indefinitely. [installStagedAtShutdown] still says so out loud if a stage is gone anyway.
     */
    const val STALE_ARTIFACT_AGE_MILLIS = 24L * 60 * 60 * 1000

    /** Name of the daemon thread that keeps a staged download alive; see [keepStagedFresh]. */
    internal const val HEARTBEAT_THREAD_NAME = "insightvm-mcp-stage-heartbeat"

    /** Longest [keepStagedFresh]'s close() waits for a tick already in progress (one setLastModified). */
    private const val HEARTBEAT_STOP_WAIT_MILLIS = 2_000L

    /** What happened, for logging and for the notification sent to the MCP client. */
    sealed interface Outcome {
        /** The new JAR is installed at the original path; the new code activates on restart. */
        data class Installed(val version: String, val path: String) : Outcome

        /**
         * The new JAR was downloaded and verified, but the running JVM holds the target file such
         * that it cannot be replaced yet. It is staged at [stagedPath] and will be swapped in when
         * this process exits — at which point [sha256] is re-checked against the file on disk, so a
         * staged file that changed in the meantime is never installed, and [targetSha256] against the
         * installed JAR, so one that somebody else has replaced since is never overwritten.
         */
        data class Staged(
            val version: String,
            val stagedPath: String,
            val sha256: String,
            /** SHA-256 of the installed JAR when this was staged: what the swap is allowed to replace. */
            val targetSha256: String,
        ) : Outcome

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
     * What an exclusive sidecar lock ([withInstallLock], [withSoleUse]) came to. Three cases, because
     * they mean different things to an operator: [Contended] is normal and transient, [Unavailable]
     * is a broken install directory that will not fix itself. A nullable result conflated them, and an
     * unwritable directory was then reported to the client, on every start, as "another process is
     * already installing an update".
     */
    internal sealed interface LockResult<out T> {
        /** The lock was held for the whole of the block, which returned [value]. */
        data class Acquired<T>(val value: T) : LockResult<T>

        /** Another process — or, within one JVM, another holder — has the lock. The block did not run. */
        data object Contended : LockResult<Nothing>

        /**
         * The lock could not be taken at all, or the block failed unexpectedly. [reason] is
         * server-authored: it names the sidecar and an exception class, never a path or a message.
         */
        data class Unavailable(val reason: String) : LockResult<Nothing>
    }

    /** `<jar><suffix>`, beside the JAR. */
    private fun sidecar(target: File, suffix: String): File = File(target.parentFile, target.name + suffix)

    /**
     * Take an exclusive, non-blocking lock on [lockFile] and run [block] under it.
     *
     * Within one JVM a second attempt on a held file throws OverlappingFileLockException rather than
     * returning null; both mean somebody else has it. Only exception CLASS names reach
     * [LockResult.Unavailable], because the messages carry filesystem paths.
     */
    private fun <T> withExclusiveLock(lockFile: File, block: () -> T): LockResult<T> {
        val file = try {
            RandomAccessFile(lockFile, "rw")
        } catch (e: Exception) {
            return LockResult.Unavailable(
                "cannot create ${lockFile.name}: ${e::class.simpleName}; is the install directory writable?",
            )
        }
        return file.use {
            val lock = try {
                file.channel.tryLock()
            } catch (e: OverlappingFileLockException) {
                null
            } catch (e: IOException) {
                return LockResult.Unavailable("cannot lock ${lockFile.name}: ${e::class.simpleName}")
            }
            if (lock == null) {
                LockResult.Contended
            } else {
                lock.use {
                    try {
                        LockResult.Acquired(block())
                    } catch (e: Exception) {
                        LockResult.Unavailable("unexpected ${e::class.simpleName} while holding ${lockFile.name}")
                    }
                }
            }
        }
    }

    /**
     * Run [block] while holding an exclusive lock on a sidecar beside [target].
     *
     * The staging file and the target JAR are machine-wide resources: the usual stdio deployment
     * starts one JVM per MCP client from the same JAR path, so an in-process flag cannot serialise
     * them. Everything from download through swap runs inside this lock.
     */
    internal fun <T> withInstallLock(target: File, block: () -> T): LockResult<T> {
        return withExclusiveLock(sidecar(target, LOCK_SUFFIX), block)
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
        // The `.running` marker (holdRunningLock) follows the same rule for the same reasons.
    }

    /**
     * Delete abandoned update artifacts beside [target] — staging files (`<jar>.*.new`) and backups
     * (`<jar>.bak`) older than [maxAgeMillis]. Only files whose name starts with the JAR's own name
     * are considered, so neighbouring servers' files are never touched. Returns what was removed.
     *
     * The `.update.lock` and `.running` sidecars are deliberately NOT swept: they are 0 bytes, they
     * block nothing once their holders exit, and unlinking one that is still held breaks the mutual
     * exclusion it exists to provide. See [withInstallLock].
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
     * This process's handle on its `<jar>.running` marker. A STRONG reference on purpose: an
     * unreachable RandomAccessFile is closed by its cleaner, and its lock silently goes with it.
     */
    private val runningMarker = AtomicReference<RandomAccessFile?>(null)

    /**
     * Declare that this process is running from [target], until it exits or calls
     * [releaseRunningLock]. Returns whether the marker is held; failing only costs the protection,
     * so this never throws.
     *
     * Where the JAR cannot be swapped atomically (Windows), an update is applied by rewriting its
     * bytes in place as a process exits. But the usual stdio deployment runs one server per MCP client
     * from the same JAR, and every one of them has it open and loads classes from it lazily: rewrite
     * it underneath them and their next first-time class load fails with an Error that no tool
     * handler catches. So every server holds a SHARED lock on `<jar>.running`, and the rewrite only
     * happens under an EXCLUSIVE one ([withSoleUse]) — that is, when nobody else is running.
     *
     * This waits rather than trying once, because the only exclusive holder is a rewrite in progress,
     * which lasts about as long as copying the JAR twice. A server started during one then holds its
     * marker like any other instead of running unprotected for the rest of its life. It may still
     * have read the half-written JAR while it started: that residual risk is documented, and only
     * versioned install paths would remove it.
     *
     * The sidecar is 0 bytes and never deleted, for the reasons given at [withInstallLock].
     */
    internal fun holdRunningLock(target: File): Boolean {
        if (runningMarker.get() != null) return true
        val file = try {
            RandomAccessFile(sidecar(target, RUNNING_SUFFIX), "rw")
        } catch (e: Exception) {
            return false
        }
        val held = try {
            file.channel.lock(0, Long.MAX_VALUE, true) != null
        } catch (e: Exception) {
            false // OverlappingFileLockException included: this JVM already holds a lock on it
        }
        if (held && runningMarker.compareAndSet(null, file)) return true
        runCatching { file.close() }
        return runningMarker.get() != null
    }

    /** Drop this process's `<jar>.running` marker, so that its own exit can take it exclusively. */
    internal fun releaseRunningLock() {
        runningMarker.getAndSet(null)?.let { runCatching { it.close() } }
    }

    /**
     * Run [block] only if no server holds its [holdRunningLock] marker on [target] — this one
     * included, so release it first. The exclusive lock is held for the whole of [block], so a server
     * starting meanwhile waits in [holdRunningLock] until the rewrite is over.
     */
    internal fun <T> withSoleUse(target: File, block: () -> T): LockResult<T> =
        withExclusiveLock(sidecar(target, RUNNING_SUFFIX), block)

    /**
     * Keep a staged download alive until this process exits and applies it. Close the result BEFORE
     * applying or deleting the stage: on Windows the pin blocks this process's own delete too.
     *
     * A stage is not applied until its process EXITS — for an MCP server, often days after the
     * download — while every other server started from the same JAR runs [cleanupStaleArtifacts] at
     * startup and deletes any `.new` older than [STALE_ARTIFACT_AGE_MILLIS]. Left alone, a sibling
     * started a day later deletes a live owner's pending update, and the owner goes on reporting
     * "restart to apply" for an update that is gone. Two defences, because neither covers every
     * platform:
     *
     *  - a **heartbeat** re-stamps the mtime every [intervalMillis] (by default a sixth of the sweep
     *    threshold, so five ticks in a row would have to be missed). This is what protects it on POSIX.
     *  - with [pin], the file is held open for reading. The JDK opens files without
     *    `FILE_SHARE_DELETE`, so on Windows another process's delete is refused outright; on POSIX,
     *    where unlink ignores open handles, it changes nothing.
     *
     * Each tick doubles as a monitor: if the file is gone anyway, [onLost] runs once and the heartbeat
     * stops. It runs on a daemon thread of its own rather than a coroutine, because it must outlive
     * every session scope and must never be what keeps the JVM alive.
     */
    internal fun keepStagedFresh(
        staged: File,
        intervalMillis: Long = STALE_ARTIFACT_AGE_MILLIS / 6,
        pin: Boolean = true,
        onLost: () -> Unit,
    ): AutoCloseable {
        val pinned = if (pin) runCatching { RandomAccessFile(staged, "r") }.getOrNull() else null
        val heartbeat = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, HEARTBEAT_THREAD_NAME).apply { isDaemon = true }
        }
        val reported = AtomicBoolean(false)
        heartbeat.scheduleWithFixedDelay(
            {
                if (staged.isFile) {
                    runCatching { staged.setLastModified(System.currentTimeMillis()) }
                } else if (reported.compareAndSet(false, true)) {
                    runCatching(onLost)
                    heartbeat.shutdown()
                }
            },
            intervalMillis,
            intervalMillis,
            TimeUnit.MILLISECONDS,
        )
        return AutoCloseable {
            heartbeat.shutdownNow()
            // Wait out a tick already running: what follows close() is the shutdown swap, which
            // overwrites and deletes the stage, and a late re-stamp must not race it.
            runCatching { heartbeat.awaitTermination(HEARTBEAT_STOP_WAIT_MILLIS, TimeUnit.MILLISECONDS) }
            runCatching { pinned?.close() }
        }
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
                // execute { }, not get(): get() buffers the ENTIRE body in memory before returning,
                // so the size stop in streamVerified would only ever see bytes the heap had already
                // accepted — an endless answer from any hop was an OutOfMemoryError in the server.
                // Leaving the block cancels whatever of the body is still unread.
                val hop = client.prepareGet(url) {
                    header(HttpHeaders.Accept, "application/octet-stream")
                    header(HttpHeaders.UserAgent, "$SERVER_NAME/$SERVER_VERSION")
                }.execute { response ->
                    if (response.status.value in 300..399) {
                        Hop.Redirect(response.headers[HttpHeaders.Location])
                    } else {
                        Hop.Final(streamVerified(response, asset, destination))
                    }
                }
                when (hop) {
                    is Hop.Final -> return hop.digest
                    is Hop.Redirect -> {
                        // Follow the CDN hop ourselves so the allow-list is re-checked for the target.
                        val location = hop.location ?: return null
                        if (++hops > MAX_REDIRECTS) return null
                        url = location
                    }
                }
            }
            @Suppress("UNREACHABLE_CODE") null
        }
    }.getOrNull()

    /** What one request in the redirect chain turned out to be, carried out of `execute { }`. */
    private sealed interface Hop {
        data class Redirect(val location: String?) : Hop
        data class Final(val digest: String?) : Hop
    }

    /**
     * Write a final (non-redirect) [response] to [destination], hashing and size-capping it as it
     * streams. Returns the SHA-256 of exactly the bytes written, or null when the response is not a
     * success or its length disagrees with what the release advertised.
     */
    private suspend fun streamVerified(
        response: HttpResponse,
        asset: UpdateChecker.ReleaseAsset,
        destination: File,
    ): String? {
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
                // Hard-stop a response that exceeds the advertised size rather than writing an
                // unbounded stream to disk. Returning ends the transfer: see downloadTo.
                if (written > asset.sizeBytes) return null
                digest.update(buffer, 0, read)
                out.write(buffer, 0, read)
            }
        }
        if (written != asset.sizeBytes) return null
        return digest.digest().toHex()
    }

    /**
     * Give [staged] the POSIX permissions of [target] before it is moved over it, and warn when the
     * move will also change the JAR's owner. Best-effort and never throws; on a filesystem without
     * POSIX permissions (Windows) there is nothing to copy.
     *
     * [Files.createTempFile] creates the stage `rw-------`, and the atomic move in [tryAtomicSwap]
     * carries that mode onto the installed JAR: every other account using a shared install then gets
     * "Unable to access jarfile". The in-place overwrite needs none of this — it writes into the
     * existing file, whose mode and owner stay as they were.
     */
    internal fun matchTargetPermissions(staged: File, target: File) {
        val posix = runCatching {
            Files.getFileStore(target.toPath()).supportsFileAttributeView(PosixFileAttributeView::class.java)
        }.getOrDefault(false)
        if (!posix) return
        runCatching { Files.setPosixFilePermissions(staged.toPath(), Files.getPosixFilePermissions(target.toPath())) }
        // This process created the stage, so the stage's owner is the account doing the update.
        val owner = runCatching { Files.getOwner(target.toPath()) }.getOrNull()
        val updater = runCatching { Files.getOwner(staged.toPath()) }.getOrNull()
        if (owner != null && updater != null && owner != updater) {
            System.err.println(
                "[insightvm-mcp] ${target.name} belongs to another account; after this update it will belong to " +
                    "the account running this server. Its permissions are kept.",
            )
        }
    }

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

        /**
         * Stream [source] over [destination]'s existing path (truncating open, never unlink), and
         * report success only once the bytes are on disk.
         */
        fun writeOver(source: File, destination: File): Boolean = runCatching {
            source.inputStream().buffered().use { input ->
                // Truncating open() on the existing path is permitted on Windows even while the JVM
                // holds the JAR, unlike rename/move — and it keeps the path's identity intact.
                FileOutputStream(destination).use { file ->
                    val output = file.buffered()
                    input.copyTo(output)
                    output.flush()
                    // On disk, not merely in the page cache. The caller deletes the backup on the
                    // strength of a verification read that the cache can answer; lose those pages to
                    // a power cut and there would be neither a good JAR nor a copy of the old one.
                    file.fd.sync()
                }
            }
            true
        }.getOrDefault(false)

        // Capture the ORIGINAL before touching it — this is the only copy of the currently working
        // server, and it is what a failed write must be rolled back to. Forced to disk like the new
        // bytes: a backup still in the page cache is no backup once the JAR itself is truncated.
        val backedUp = writeOver(target, backup) && backup.length() == target.length()
        if (!backedUp) {
            System.err.println("[insightvm-mcp] Could not back up ${target.name}; refusing to overwrite it.")
            return false
        }

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
        val locked = withInstallLock(target) {
            cleanupStaleArtifacts(target)
            // What this update is meant to replace. A stage can wait days for its process to exit,
            // and the shutdown swap refuses to write over anything else; see installStagedAtShutdown.
            val targetSha256 = sha256Of(target)
                ?: return@withInstallLock Outcome.Failed("could not read ${target.name}, so an update cannot be checked against it")
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

            // Only the verified bytes change hands, never createTempFile's owner-only mode.
            matchTargetPermissions(staged, target)
            if (tryAtomicSwap(staged, target)) {
                Outcome.Installed(version, target.absolutePath)
            } else {
                Outcome.Staged(version, staged.absolutePath, asset.sha256, targetSha256)
            }
        }
        when (locked) {
            is LockResult.Acquired -> locked.value
            LockResult.Contended -> Outcome.Failed("another process is already installing an update")
            is LockResult.Unavailable -> Outcome.Failed(locked.reason)
        }
    }

    /**
     * Complete a [Outcome.Staged] install as the JVM exits, when overwriting the JAR in place is
     * safe because class loading is finished. Best-effort, but never silent: an update that was
     * promised and then not applied is said so on stderr, since nothing else will mention it.
     *
     * [targetSha256] is [Outcome.Staged.targetSha256]. The caller must have closed
     * [keepStagedFresh]'s handle: on Windows it holds the stage open, which blocks deleting it.
     */
    fun installStagedAtShutdown(staged: File, target: File, expectedSha256: String, targetSha256: String): Boolean {
        if (!staged.isFile) {
            // keepStagedFresh makes this rare, but a sibling's sweep is still the likeliest cause —
            // a heartbeat that could not run, a filesystem that ignores the pin. Silence here looks
            // like "the update just never happened"; name it so the cause is visible and
            // STALE_ARTIFACT_AGE_MILLIS is the obvious dial.
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
        val locked = withInstallLock(target) {
            // Staged possibly days ago. If the JAR is no longer what this update was meant to replace,
            // somebody has installed something since — most likely NEWER, by a sibling server.
            // Writing this copy over it would be a silent downgrade, possibly past a security fix.
            if (sha256Of(target) != targetSha256) {
                System.err.println("[insightvm-mcp] ${target.name} changed since this update was staged; not overwriting it.")
                runCatching { staged.delete() }
                return@withInstallLock false
            }
            // This process's own marker goes first, or it would be the "other server" it waits for.
            releaseRunningLock()
            when (val sole = withSoleUse(target) { overwriteInPlace(staged, target, expectedSha256) }) {
                is LockResult.Acquired -> sole.value
                LockResult.Contended -> {
                    System.err.println(
                        "[insightvm-mcp] Another server is still running from ${target.name}; not overwriting it. " +
                            "The update will be re-staged on a later start.",
                    )
                    runCatching { staged.delete() }
                    false
                }

                is LockResult.Unavailable -> {
                    System.err.println(
                        "[insightvm-mcp] Could not check for other servers running from ${target.name} " +
                            "(${sole.reason}); not overwriting it.",
                    )
                    false
                }
            }
        }
        return when (locked) {
            is LockResult.Acquired -> locked.value
            LockResult.Contended -> {
                System.err.println("[insightvm-mcp] Another process is installing an update; the staged update was not applied.")
                false
            }

            is LockResult.Unavailable -> {
                System.err.println("[insightvm-mcp] The staged update was not applied (${locked.reason})")
                false
            }
        }
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
