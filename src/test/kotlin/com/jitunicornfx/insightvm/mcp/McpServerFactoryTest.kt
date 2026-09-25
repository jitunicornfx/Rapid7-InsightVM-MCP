package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.CatalogTools
import com.jitunicornfx.insightvm.mcp.testutil.TEST_CATALOGS
import com.jitunicornfx.insightvm.mcp.testutil.testConfig
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class McpServerFactoryTest {

    private fun client(config: Config) = Rapid7Client(
        config,
        consoleEngine = MockEngine { respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
        cloudEngine = MockEngine { respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) },
    )

    @Test
    fun `full registration counts`() {
        val config = testConfig()
        val built = buildInsightVmServer(client(config), config, TEST_CATALOGS)
        // 343 ops minus the gated admin command and the six gated secret tools.
        assertEquals(336, built.selected.size)
        assertEquals("registered 336/343 API tools (console=323, cloud=13)", built.summary)
        assertEquals(323, built.selected.count { it.family == ApiFamily.CONSOLE })

        val open = testConfig(filter = ToolFilter(allowAdminCommands = true, allowSecretTools = true))
        val all = buildInsightVmServer(client(open), open, TEST_CATALOGS)
        assertEquals("registered 343/343 API tools (console=330, cloud=13) [ADMIN COMMANDS ENABLED, SECRET TOOLS ENABLED]", all.summary)
    }

    @Test
    fun `console-only and cloud-only`() {
        val consoleOnly = testConfig(cloud = null)
        val b1 = buildInsightVmServer(client(consoleOnly), consoleOnly)
        assertEquals(323, b1.selected.size)
        assertEquals("registered 323/330 API tools (console=323)", b1.summary)

        val cloudOnly = testConfig(console = null)
        val b2 = buildInsightVmServer(client(cloudOnly), cloudOnly)
        assertEquals(13, b2.selected.size)
        assertTrue(b2.selected.all { it.op.name.startsWith("cloud_") })
    }

    @Test
    fun `filters are reflected in the summary`() {
        val config = testConfig(filter = ToolFilter(readOnly = true, tags = setOf("Site"), allowAdminCommands = true))
        val built = buildInsightVmServer(client(config), config, TEST_CATALOGS)
        assertTrue(built.selected.all { it.op.readOnly })
        assertContains(built.summary, "read-only")
        assertContains(built.summary, "tags=Site")
        assertContains(built.summary, "ADMIN COMMANDS ENABLED")
    }

    @Test
    fun `server info and tool groups helpers`() {
        val config = testConfig(console = null)
        val built = buildInsightVmServer(client(config), config, TEST_CATALOGS.filterKeys { it == ApiFamily.CLOUD })
        val info = CatalogTools.serverInfo(config, TEST_CATALOGS.filterKeys { it == ApiFamily.CLOUD }, built.selected).toString()
        assertContains(info, "\"configured\":false")
        assertContains(info, "\"registeredTools\":13")
        assertContains(info, "\"totalTools\":15")
        val groups = CatalogTools.toolGroups(built.selected, "scan").toString()
        assertContains(groups, "\"count\":8")
        assertContains(groups, "cloud_stop_scan")
        assertEquals("[]", CatalogTools.toolGroups(built.selected, "nope").toString())
    }

    /**
     * Regression: --http builds a Server for every session, and each one built its own copy of every
     * tool's name, description, schema and annotations (about 430K characters of tools/list text).
     */
    @Test
    fun `servers built from one preparation share their tool definitions`() {
        val config = testConfig()
        val prepared = CatalogTools.prepare(config, TEST_CATALOGS)
        val a = buildInsightVmServer(client(config), prepared)
        val b = buildInsightVmServer(client(config), prepared)
        assertEquals(a.server.tools.keys, b.server.tools.keys)
        assertEquals(336 + prepared.metaToolCount, a.server.tools.size)
        for ((name, registered) in a.server.tools) {
            assertSame(registered.tool, b.server.tools.getValue(name).tool, name)
        }
        // Only the handlers are per Server: each is bound to its own session's calls.
        val handler = a.server.tools.getValue("get_assets").handler
        assertTrue(handler !== b.server.tools.getValue("get_assets").handler)
        assertEquals(a.summary, b.summary)
    }

    @Test
    fun `constants`() {
        assertEquals("rapid7-insightvm-mcp", SERVER_NAME)
        // SERVER_VERSION is deliberately not asserted here: comparing it to a literal would only
        // check one constant against another and would keep passing while build.gradle.kts drifted
        // away from both. The Gradle `verifyServerVersion` task enforces that agreement instead.
        assertEquals("$SERVER_NAME.update", UPDATE_LOGGER_NAME)
    }
}
