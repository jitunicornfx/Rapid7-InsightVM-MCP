package com.jitunicornfx.insightvm.mcp

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [UpdateStatus] and the `update` object `insightvm_server_info` renders from it: the answer a client
 * can ask for when the update notice, a push, never reached it.
 */
class UpdateStatusTest {

    @BeforeTest
    @AfterTest
    fun reset() {
        UpdateStatus.reset()
    }

    private val available = UpdateChecker.Result(updateAvailable = true, currentVersion = "0.2.1", latestVersion = "9.9.9")

    private fun info(): JsonObject = updateInfo(UpdateStatus.active)

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    @Test
    fun `a check still running says so, and names the running version`() {
        val info = info()
        assertEquals(SERVER_VERSION, info.text("currentVersion"))
        assertEquals("pending", info.text("check"))
        assertEquals("false", info.text("updateAvailable"))
        assertEquals("notAttempted", info.text("install"))
        assertEquals("false", info.text("restartRequired"))
        assertNull(info["latestRelease"])
        assertEquals(UpdateChecker.RELEASES_PAGE_URL, info.text("releaseUrl"))
        assertContains(info.text("summary")!!, "has not finished yet")
    }

    @Test
    fun `an available release is reported with its version`() {
        UpdateStatus.recordCheck(available)
        val info = info()
        assertEquals("completed", info.text("check"))
        assertEquals("9.9.9", info.text("latestRelease"))
        assertEquals("true", info.text("updateAvailable"))
        assertContains(info.text("summary")!!, "9.9.9 (currently running 0.2.1)")
    }

    @Test
    fun `up to date and could-not-tell are different answers`() {
        // GitHub named the running release: up to date, and the latest release is known.
        UpdateStatus.recordCheck(UpdateChecker.evaluate("""{"tag_name":"v0.2.1"}""", "0.2.1"))
        assertEquals("completed", info().text("check"))
        assertEquals("0.2.1", info().text("latestRelease"))
        assertContains(info().text("summary")!!, "is up to date")

        // The checker degrades every failure to "no update" with no release named. Recorded as
        // completed, that would claim "up to date" for a server that could not reach GitHub.
        UpdateStatus.reset()
        UpdateStatus.recordCheck(UpdateChecker.evaluate(null, "0.2.1"))
        assertEquals("failed", info().text("check"))
        assertNull(info()["latestRelease"])
        assertFalse(info().text("summary")!!.contains("up to date"), info().text("summary"))
        assertContains(info().text("summary")!!, "not known")
    }

    @Test
    fun `a late failure never erases a recorded result, and a disabled check says how it was disabled`() {
        UpdateStatus.markCheckStarted()
        UpdateStatus.recordCheck(available)
        UpdateStatus.markCheckFailed()
        assertEquals(UpdateStatus.CheckState.COMPLETED, UpdateStatus.active.checkState)

        UpdateStatus.reset()
        UpdateStatus.markCheckStarted()
        UpdateStatus.markCheckFailed()
        assertEquals("failed", info().text("check"))

        UpdateStatus.reset()
        UpdateStatus.markCheckDisabled()
        assertEquals("disabled", info().text("check"))
        assertContains(info().text("summary")!!, Config.ENV_DISABLE_UPDATE_CHECK)
    }

    @Test
    fun `an installed release needs only a restart`() {
        UpdateStatus.recordCheck(available)
        UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "/opt/insightvm/app.jar"))
        val info = info()
        assertEquals("installed", info.text("install"))
        assertEquals("9.9.9", info.text("installedVersion"))
        assertEquals("true", info.text("restartRequired"))
        assertNull(info["appliesOnExit"], "only a staged install has one")
        assertContains(info.text("summary")!!, "has been installed. Restart the server to run it.")
        assertFalse(info.toString().contains("/opt/insightvm"), "no path reaches the model")
    }

    @Test
    fun `a staged release needs a restart only once its shutdown hook is registered, and not after it is lost`() {
        UpdateStatus.recordCheck(available)
        UpdateStatus.recordInstall(UpdateInstaller.Outcome.Staged("9.9.9", "/opt/insightvm/app.jar.new", "a".repeat(64), "b".repeat(64)))
        assertEquals("staged", info().text("install"))
        assertEquals("false", info().text("appliesOnExit"))
        assertEquals("false", info().text("restartRequired"))
        assertContains(info().text("summary")!!, "will NOT be applied automatically")

        UpdateStatus.markStagedAppliesOnExit()
        assertEquals("true", info().text("appliesOnExit"))
        assertEquals("true", info().text("restartRequired"))
        assertContains(info().text("summary")!!, "will be applied when this server exits")
        assertFalse(info().toString().contains("/opt/insightvm"), "no path reaches the model")

        UpdateStatus.markStagedLost()
        assertEquals("failed", info().text("install"))
        assertEquals("false", info().text("restartRequired"))
        assertEquals(UpdateStatus.STAGED_LOST_REASON, info().text("failureReason"))
    }

    @Test
    fun `only a staged install can be lost`() {
        UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "/opt/app.jar"))
        UpdateStatus.markStagedLost()
        assertEquals(UpdateStatus.InstallState.INSTALLED, UpdateStatus.active.installState)
        assertTrue(UpdateStatus.active.restartRequired)
    }

    @Test
    fun `failed, skipped and switched-off installs each say what happened`() {
        UpdateStatus.recordInstall(UpdateInstaller.Outcome.Failed("SHA-256 mismatch for 9.9.9 — refusing to install"))
        assertEquals("failed", info().text("install"))
        assertEquals("SHA-256 mismatch for 9.9.9 — refusing to install", info().text("failureReason"))
        assertContains(info().text("summary")!!, "Automatic update did not complete: SHA-256 mismatch")

        UpdateStatus.recordInstall(UpdateInstaller.Outcome.Skipped)
        assertEquals("skipped", info().text("install"))
        assertContains(info().text("summary")!!, "nothing to install")

        UpdateStatus.markAutoInstallDisabled()
        assertEquals("disabled", info().text("install"))
        assertContains(info().text("summary")!!, Config.ENV_DISABLE_AUTO_UPDATE)
    }

    @Test
    fun `the checker names the newest release whether or not it is newer`() {
        assertEquals("0.3.0", UpdateChecker.evaluate("""{"tag_name":"v0.3.0"}""", "0.2.1").latestRelease)
        assertEquals("0.2.1", UpdateChecker.evaluate("""{"tag_name":"v0.2.1"}""", "0.2.1").latestRelease)
        assertEquals("0.2.0", UpdateChecker.evaluate("""{"tag_name":"0.2.0"}""", "0.2.1").latestRelease)
        assertNull(UpdateChecker.evaluate("""{"tag_name":"not a version"}""", "0.2.1").latestRelease)
        assertNull(UpdateChecker.evaluate(null, "0.2.1").latestRelease)
        // A result built by hand with a newer version names it too.
        assertEquals("9.9.9", available.latestRelease)
    }
}
