package com.jitunicornfx.insightvm.mcp

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import io.ktor.server.sse.sse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

/** How long a legacy stream's end waits for its Server to close. */
private const val CLOSE_TIMEOUT_MILLIS = 1_000L

/**
 * The legacy HTTP+SSE transport (GET [path] opens the event stream, POST [path]?sessionId=… carries
 * client messages), mounted so that it works for every client.
 *
 * The SDK's own `Route.mcp(path)` announces a *relative* endpoint (`?sessionId=…`). Browsers and the
 * TypeScript SDK resolve that against the stream URL (→ `/sse?sessionId=…`), but the Kotlin SDK client
 * resolves it against the stream URL's parent (→ `/?sessionId=…`), which 404s. Announcing the absolute
 * path removes the ambiguity. Otherwise this mirrors the SDK helper: one [Server] per connection, a
 * session map keyed by the transport's session id, entries removed when the server closes.
 *
 * The stream and its Server end together. The SDK helper waits for cancellation alone, so a Server
 * closed from outside (the `--http` session cap, [ServerGovernor]) left its stream handler suspended
 * and the Server reachable from it; here the stream ends, and the client sees it end. The other way
 * round, a stream that ends (the handler is cancelled) closes its Server, which the cap then stops
 * counting. Ktor does not cancel it when a client silently drops an idle stream, which is why the
 * cap, not this, is what bounds such Servers.
 *
 * Requires the Ktor `SSE` plugin to be installed (done by `mcpStreamableHttp`).
 */
fun Route.legacySseTransport(
    path: String,
    maxRequestBodySize: Long = HttpSecurity.DEFAULT_MAX_BODY_BYTES,
    newServer: () -> Server,
) {
    val transports = ConcurrentHashMap<String, SseServerTransport>()

    sse(path) {
        val transport = SseServerTransport(path, this, maxRequestBodySize)
        transports[transport.sessionId] = transport
        val server = newServer()
        val closed = CompletableDeferred<Unit>()
        server.onClose {
            transports.remove(transport.sessionId)
            closed.complete(Unit)
        }
        try {
            server.createSession(transport)
            closed.await()
        } finally {
            transports.remove(transport.sessionId)
            // Bounded: this also runs as the engine stops, which must not wait on a dead connection.
            if (!closed.isCompleted) {
                withContext(NonCancellable) { withTimeoutOrNull(CLOSE_TIMEOUT_MILLIS) { runCatching { server.close() } } }
            }
        }
    }

    post(path) {
        val sessionId = call.request.queryParameters["sessionId"]
        if (sessionId == null) {
            call.respond(HttpStatusCode.BadRequest, "sessionId query parameter is not provided")
            return@post
        }
        val transport = transports[sessionId]
        if (transport == null) {
            call.respond(HttpStatusCode.NotFound, "Session not found")
            return@post
        }
        transport.handlePostMessage(call)
    }
}
