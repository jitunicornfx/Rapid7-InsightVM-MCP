package com.jitunicornfx.insightvm.mcp

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.concurrent.atomic.AtomicReference

/**
 * What this process knows about updates, kept so `insightvm_server_info` can answer from it.
 *
 * The update notices are pushes, and a push is best-effort: over Streamable HTTP a message the server
 * sends while the client has no event stream open is dropped, not queued, and a client that never
 * opens one never gets it. The server info tool is a request the client makes, so this is the
 * authoritative answer and the notices are a courtesy.
 *
 * Process-wide, like [ResultBudget] and [SpoolStore]: `--http` builds a Server per session, but there
 * is one startup check and at most one install attempt per process. It holds no `Deferred` and
 * nothing here suspends, so a tool handler reading [active] can never wait on a check in flight.
 */
object UpdateStatus {

    enum class CheckState {
        /** `INSIGHTVM_DISABLE_UPDATE_CHECK` / `--no-update-check`: no check was started. */
        DISABLED,

        /** The check was started and has not reported yet. */
        PENDING,

        /** GitHub named its newest release; see [Snapshot.result]. */
        COMPLETED,

        /** The check ended without a usable answer (offline, rate limited, a malformed payload, shutdown). */
        FAILED,
    }

    enum class InstallState { NOT_ATTEMPTED, DISABLED, INSTALLED, STAGED, FAILED, SKIPPED }

    /** An immutable view, swapped atomically. Every string in it is server-authored or allow-listed. */
    data class Snapshot(
        val checkState: CheckState = CheckState.PENDING,
        /** The check's result; its versions have passed [UpdateChecker]'s allow-list. */
        val result: UpdateChecker.Result? = null,
        val installState: InstallState = InstallState.NOT_ATTEMPTED,
        /** The version installed or staged, allow-listed by [UpdateChecker] before it reached here. */
        val installedVersion: String? = null,
        /** Fixed text from [UpdateInstaller.Outcome.Failed] or [STAGED_LOST_REASON]; never remote content. */
        val failureReason: String? = null,
        /**
         * For a STAGED install: whether the shutdown hook that applies it was registered. False when
         * the JVM was already shutting down, in which case the staged file is not applied.
         */
        val appliesOnExit: Boolean = false,
    ) {
        /** True when new code is on disk and only a restart is needed to run it. */
        val restartRequired: Boolean
            get() = installState == InstallState.INSTALLED || (installState == InstallState.STAGED && appliesOnExit)
    }

    private val state = AtomicReference(Snapshot())

    /** The process-wide snapshot. Cheap, non-blocking, safe from any thread. */
    val active: Snapshot get() = state.get()

    fun markCheckDisabled() = update { it.copy(checkState = CheckState.DISABLED) }

    fun markCheckStarted() = update { it.copy(checkState = CheckState.PENDING) }

    /** Only downgrades a PENDING state, so a late cancellation cannot erase a recorded result. */
    fun markCheckFailed() = update {
        if (it.checkState == CheckState.PENDING) it.copy(checkState = CheckState.FAILED) else it
    }

    /**
     * [UpdateChecker.check] never throws: on any failure it reports "no update" with no release
     * named. Recorded as COMPLETED, that would read as "up to date" when nothing is known.
     */
    fun recordCheck(result: UpdateChecker.Result) = update {
        val answered = result.updateAvailable || result.latestRelease != null
        it.copy(checkState = if (answered) CheckState.COMPLETED else CheckState.FAILED, result = result)
    }

    fun markAutoInstallDisabled() = update { it.copy(installState = InstallState.DISABLED) }

    fun recordInstall(outcome: UpdateInstaller.Outcome) = update { current ->
        when (outcome) {
            is UpdateInstaller.Outcome.Installed ->
                current.copy(installState = InstallState.INSTALLED, installedVersion = outcome.version)

            // appliesOnExit stays false until the shutdown hook is actually registered.
            is UpdateInstaller.Outcome.Staged ->
                current.copy(installState = InstallState.STAGED, installedVersion = outcome.version)

            is UpdateInstaller.Outcome.Failed ->
                current.copy(installState = InstallState.FAILED, failureReason = outcome.reason)

            UpdateInstaller.Outcome.Skipped -> current.copy(installState = InstallState.SKIPPED)
        }
    }

    /** The shutdown hook that applies a staged install has been registered. */
    fun markStagedAppliesOnExit() = update { it.copy(appliesOnExit = true) }

    /**
     * The staged download vanished before this process could apply it; see
     * [UpdateInstaller.keepStagedFresh]. Without this the status would promise, for the rest of the
     * process, that a restart applies the update. Only a STAGED install can be lost.
     */
    fun markStagedLost() = update {
        if (it.installState != InstallState.STAGED) {
            it
        } else {
            it.copy(installState = InstallState.FAILED, failureReason = STAGED_LOST_REASON, appliesOnExit = false)
        }
    }

    /** Fixed, server-authored text: it reaches the model through `insightvm_server_info`. */
    const val STAGED_LOST_REASON =
        "the verified download was removed from disk before it could be applied; it will be downloaded again on the next check"

    /** Restore the initial snapshot. Tests only: the holder is process-wide. */
    internal fun reset() = state.set(Snapshot())

    // updateAndGet, not a read-modify-write: the check and the install record from different threads.
    private fun update(transform: (Snapshot) -> Snapshot) {
        state.updateAndGet(transform)
    }
}

/**
 * The `update` object of `insightvm_server_info`.
 *
 * SECURITY INVARIANT: every string here is server-authored or a version that passed
 * [UpdateChecker]'s allow-list, which is why the tool returns it without the untrusted-data fence.
 * No path appears: not the JAR's, not the staged file's.
 */
internal fun updateInfo(snapshot: UpdateStatus.Snapshot): JsonObject = buildJsonObject {
    put("currentVersion", SERVER_VERSION)
    put("check", snapshot.checkState.name.lowercase())
    snapshot.result?.latestRelease?.let { put("latestRelease", it) }
    put("updateAvailable", snapshot.result?.updateAvailable ?: false)
    put("releaseUrl", snapshot.result?.releaseUrl ?: UpdateChecker.RELEASES_PAGE_URL)
    put("install", snapshot.installState.camelCase())
    snapshot.installedVersion?.let { put("installedVersion", it) }
    if (snapshot.installState == UpdateStatus.InstallState.STAGED) put("appliesOnExit", snapshot.appliesOnExit)
    snapshot.failureReason?.let { put("failureReason", it) }
    put("restartRequired", snapshot.restartRequired)
    put("summary", updateSummary(snapshot))
}

/**
 * One server-authored sentence or two describing [snapshot]. The install wording matches
 * [notifyUpdateInstalled]'s, so the tool and the notice tell an operator the same thing.
 */
internal fun updateSummary(snapshot: UpdateStatus.Snapshot): String {
    val check = when (snapshot.checkState) {
        UpdateStatus.CheckState.DISABLED ->
            "The update check is disabled (${Config.ENV_DISABLE_UPDATE_CHECK} / --no-update-check), so whether a newer " +
                "release exists is not known."

        UpdateStatus.CheckState.PENDING -> "The update check has not finished yet; ask again in a moment."

        UpdateStatus.CheckState.FAILED ->
            "The update check could not get an answer from GitHub, so whether a newer release exists is not known."

        UpdateStatus.CheckState.COMPLETED -> snapshot.result?.message() ?: "The update check completed but reported nothing."
    }
    val install = when (snapshot.installState) {
        UpdateStatus.InstallState.INSTALLED ->
            "Version ${snapshot.installedVersion} has been installed. Restart the server to run it."

        UpdateStatus.InstallState.STAGED -> if (snapshot.appliesOnExit) {
            "Version ${snapshot.installedVersion} has been downloaded and verified, and will be applied when this server " +
                "exits. Restart the server to run it."
        } else {
            "Version ${snapshot.installedVersion} has been downloaded and verified but will NOT be applied automatically, " +
                "because the server was already shutting down. Update it manually."
        }

        UpdateStatus.InstallState.FAILED -> "Automatic update did not complete: ${snapshot.failureReason}"

        UpdateStatus.InstallState.DISABLED ->
            "Automatic installation is disabled (${Config.ENV_DISABLE_AUTO_UPDATE} / --no-auto-update); update it manually."

        UpdateStatus.InstallState.SKIPPED -> "There was nothing to install for the available release."

        UpdateStatus.InstallState.NOT_ATTEMPTED -> null
    }
    return if (install == null) check else "$check $install"
}

/** `NOT_ATTEMPTED` -> `notAttempted`; a single word is simply lower-cased. */
private fun Enum<*>.camelCase(): String = name.lowercase()
    .split('_')
    .mapIndexed { index, part -> if (index == 0) part else part.replaceFirstChar { it.uppercase() } }
    .joinToString("")
