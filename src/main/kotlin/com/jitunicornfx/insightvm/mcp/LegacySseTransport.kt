package com.jitunicornfx.insightvm.mcp

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import io.ktor.server.sse.sse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import kotlinx.coroutines.awaitCancellation
import java.util.concurrent.ConcurrentHashMap

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
        server.onClose { transports.remove(transport.sessionId) }
        try {
            server.createSession(transport)
            awaitCancellation()
        } finally {
            transports.remove(transport.sessionId)
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
