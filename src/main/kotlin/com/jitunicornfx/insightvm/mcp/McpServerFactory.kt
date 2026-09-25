package com.jitunicornfx.insightvm.mcp

import com.jitunicornfx.insightvm.mcp.catalog.ApiFamily
import com.jitunicornfx.insightvm.mcp.catalog.Catalog
import com.jitunicornfx.insightvm.mcp.catalog.CatalogFilter
import com.jitunicornfx.insightvm.mcp.catalog.CatalogLoader
import com.jitunicornfx.insightvm.mcp.catalog.CatalogTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.ServerSession
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.LoggingLevel
import io.modelcontextprotocol.kotlin.sdk.types.LoggingMessageNotification
import io.modelcontextprotocol.kotlin.sdk.types.LoggingMessageNotificationParams
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

const val SERVER_NAME = "rapid7-insightvm-mcp"
const val SERVER_VERSION = "0.2.1"

/** Clients tend to struggle above this many tools; the startup log suggests filters when exceeded. */
const val LARGE_TOOL_SET_THRESHOLD = 128

/** The outcome of building a server: the server plus what got registered, for logging and tests. */
data class BuiltServer(val server: Server, val selected: List<CatalogFilter.Selection>, val summary: String)

/**
 * Build a fully-configured MCP [Server] with every selected InsightVM catalog operation registered
 * as a tool. The [client] is shared by all tool handlers.
 */
fun buildInsightVmServer(
    client: Rapid7Client,
    config: Config,
    catalogs: Map<ApiFamily, Catalog> = CatalogLoader.loadAll(config.activeFamilies),
    spool: SpoolStore = SpoolStore.active,
): BuiltServer = buildInsightVmServer(client, CatalogTools.prepare(config, catalogs), spool)

/**
 * Build a Server from tool definitions [CatalogTools.prepare] already built. `--http` builds one
 * Server per session, and they all share [prepared]'s definitions.
 */
fun buildInsightVmServer(
    client: Rapid7Client,
    prepared: CatalogTools.Prepared,
    spool: SpoolStore = SpoolStore.active,
): BuiltServer {
    val server = Server(
        Implementation(name = SERVER_NAME, version = SERVER_VERSION),
        ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = false),
                // Required to push notifications/message to the client (e.g. the update notice).
                logging = buildJsonObject { },
            ),
        ),
    )
    val selected = CatalogTools.register(server, client, prepared, spool)
    return BuiltServer(server, selected, registrationSummary(prepared))
}

/** The one-line account of what [prepared] registers, as the startup log prints it. */
internal fun registrationSummary(prepared: CatalogTools.Prepared): String {
    val config = prepared.config
    return CatalogFilter.summarize(prepared.selected, prepared.catalogs, config.filter.copy(families = config.activeFamilies))
}

/** Logger name carried on the update notification, so clients can attribute/filter it. */
const val UPDATE_LOGGER_NAME = "$SERVER_NAME.update"

/**
 * Arrange for every session of this server to receive the update notification once initialized.
 *
 * Used by the HTTP transport, where the SDK creates sessions internally and exposes no per-session
 * callback: [Server.onConnect] fires as connections arrive, so each newly-seen session in
 * [Server.sessions] gets its [ServerSession.onInitialized] hook registered exactly once.
 */
fun Server.attachUpdateNotifier(
    scope: CoroutineScope,
    notify: suspend (ServerSession) -> Unit,
) {
    val handled = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    onConnect {
        sessions.values.forEach { session ->
            if (handled.add(session.sessionId)) {
                session.onInitialized { scope.launch { runCatching { notify(session) } } }
            }
        }
    }
}

/**
 * Send [result] to [session] as an MCP `notifications/message` once the client has finished
 * initializing, when — and only when — an update is available.
 *
 * Delivery is best-effort. Over Streamable HTTP a server-initiated message travels on an event
 * stream the client opens, and one sent while no stream is open is dropped, not queued (the HTTP
 * runtime waits [HTTP_NOTIFY_GRACE_MILLIS] first for that reason). A client may also never show it.
 * `insightvm_server_info` reports the same state ([UpdateStatus]) on request.
 */
suspend fun Server.notifyUpdateAvailable(session: ServerSession, result: UpdateChecker.Result) {
    if (!result.updateAvailable) return
    runCatching {
        sendLoggingMessage(
            session.sessionId,
            LoggingMessageNotification(
                LoggingMessageNotificationParams(
                    level = LoggingLevel.Info,
                    logger = UPDATE_LOGGER_NAME,
                    data = buildJsonObject {
                        put("message", JsonPrimitive(result.message()))
                        put("current_version", JsonPrimitive(result.currentVersion))
                        result.latestVersion?.let { put("latest_version", JsonPrimitive(it)) }
                        put("release_url", JsonPrimitive(result.releaseUrl))
                    },
                ),
            ),
        )
    }.onFailure { System.err.println("[insightvm-mcp] Update notification not delivered: ${it.message}") }
}

/**
 * Tell the client the result of an automatic installation. Every string here is server-authored —
 * the version has already passed [UpdateChecker]'s strict allow-list and failure reasons are fixed
 * text — so no remote content is forwarded to the model.
 */
suspend fun Server.notifyUpdateInstalled(session: ServerSession, outcome: UpdateInstaller.Outcome) {
    val (level, message) = when (outcome) {
        is UpdateInstaller.Outcome.Installed ->
            LoggingLevel.Info to "Version ${outcome.version} has been installed. Restart the server to run it."

        is UpdateInstaller.Outcome.Staged ->
            LoggingLevel.Info to
                "Version ${outcome.version} has been downloaded and verified, and will be applied " +
                "when this server exits. Restart the server to run it."

        is UpdateInstaller.Outcome.Failed ->
            LoggingLevel.Warning to "Automatic update did not complete: ${outcome.reason}"

        UpdateInstaller.Outcome.Skipped -> return
    }
    runCatching {
        sendLoggingMessage(
            session.sessionId,
            LoggingMessageNotification(
                LoggingMessageNotificationParams(
                    level = level,
                    logger = UPDATE_LOGGER_NAME,
                    data = buildJsonObject {
                        put("message", JsonPrimitive(message))
                        put("restart_required", JsonPrimitive(outcome is UpdateInstaller.Outcome.Installed || outcome is UpdateInstaller.Outcome.Staged))
                    },
                ),
            ),
        )
    }.onFailure { System.err.println("[insightvm-mcp] Install notification not delivered: ${it.message}") }
}
