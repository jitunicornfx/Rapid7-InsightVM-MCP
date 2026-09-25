package com.jitunicornfx.insightvm.mcp

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Caps how many MCP [Server]s the `--http` transport keeps alive, closing the oldest when a new one
 * would pass [maxLive].
 *
 * Both HTTP transports build a Server for every session: Streamable HTTP for every POST that carries
 * no `Mcp-Session-Id`, the legacy transport for every event stream. The SDK forgets a Streamable
 * HTTP session only when the client sends DELETE, and most clients simply exit, so a long-running
 * `--http` server kept one Server per reconnect for the rest of its life.
 *
 * A limit that refused new sessions would turn those abandoned ones into a permanent lock-out, and
 * the SDK exposes no idle time to expire them by. Closing the oldest instead bounds memory and keeps
 * the server open to new clients. Closing a Server closes its session and the SDK forgets its id, so
 * a client that does come back with it gets 404, which the Streamable HTTP specification answers by
 * initializing again; a legacy client sees its event stream end.
 *
 * A Server whose session ends (a DELETE, or a legacy stream the server sees end) leaves the count at
 * once. Everything else stays counted until it is evicted, which is the bound this class exists to
 * keep: a client that never finished initializing, and a legacy client that dropped its stream, since
 * Ktor's CIO engine does not notice a client leaving a stream nothing is being written to.
 *
 * A Server whose session never initialized is evicted before any that did. The SDK builds one for
 * every sessionless POST before it reads the body, so a probe or a buggy client posting anything but
 * `initialize` gets a Server too, answered 400 and never registered; counted like a live session, each
 * one past the cap closed the oldest real client. Among the uninitialized, the oldest goes first — a
 * real client is uninitialized only for its handshake — and the newcomer itself is never its own victim.
 */
internal class ServerGovernor(
    val maxLive: Int,
    /** Where evicted Servers are closed: the runtime's own scope, cancelled at shutdown. */
    private val scope: CoroutineScope,
) {
    init {
        require(maxLive >= 1) { "maxLive must be at least 1" }
    }

    /** Insertion-ordered, so the first element is the oldest. Guarded by itself. */
    private val live = LinkedHashSet<Server>()

    /** The members of [live] whose session has finished initializing. Guarded by [live]. */
    private val initialized = HashSet<Server>()

    /** How many Servers are currently counted against [maxLive]. */
    val liveCount: Int get() = synchronized(live) { live.size }

    /** Count [server] against the cap, closing the oldest ones if it is now passed; returns [server]. */
    fun admit(server: Server): Server {
        server.onClose { release(server) }
        // Each Server here has exactly one session. Ending it (DELETE, a closed legacy stream) does not
        // close the Server, so watch the session too.
        val watching = AtomicBoolean(false)
        server.onConnect {
            if (watching.compareAndSet(false, true)) {
                server.sessions.values.forEach { session ->
                    session.onClose { release(server) }
                    // onInitialized chains onto any earlier handler (the update notifier's), it does not replace it.
                    session.onInitialized { markInitialized(server) }
                }
            }
        }
        val evicted = synchronized(live) {
            live += server
            buildList {
                while (live.size > maxLive) {
                    // live.first() is never the newcomer here: live holds at least two when over a cap of one or more.
                    val victim = live.firstOrNull { it !in initialized && it !== server } ?: live.first()
                    live.remove(victim)
                    initialized.remove(victim)
                    add(victim)
                }
            }
        }
        // Released above rather than by its onClose: Server.close() stops at the first session that
        // fails to close, before its own onClose callbacks run.
        evicted.forEach { oldest -> scope.launch { runCatching { oldest.close() } } }
        return server
    }

    private fun markInitialized(server: Server) {
        synchronized(live) { if (server in live) initialized += server }
    }

    private fun release(server: Server) {
        synchronized(live) {
            live.remove(server)
            initialized.remove(server)
        }
    }
}
