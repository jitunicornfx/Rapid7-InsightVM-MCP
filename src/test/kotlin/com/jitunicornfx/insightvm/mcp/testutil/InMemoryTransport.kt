package com.jitunicornfx.insightvm.mcp.testutil

import io.modelcontextprotocol.kotlin.sdk.shared.AbstractTransport
import io.modelcontextprotocol.kotlin.sdk.shared.TransportSendOptions
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCMessage

/**
 * In-process transport pair for wiring an MCP [io.modelcontextprotocol.kotlin.sdk.client.Client] and
 * [io.modelcontextprotocol.kotlin.sdk.server.Server] together inside one test JVM — no sockets, no
 * subprocess. Adapted from the MCP Kotlin SDK's own test utilities (that helper is test-only and not
 * published in the artifact).
 */
class InMemoryTransport : AbstractTransport() {
    private var other: InMemoryTransport? = null
    private val queued: MutableList<JSONRPCMessage> = mutableListOf()

    companion object {
        /** One transport goes to the Client, the other to the Server. */
        fun createLinkedPair(): Pair<InMemoryTransport, InMemoryTransport> {
            val a = InMemoryTransport()
            val b = InMemoryTransport()
            a.other = b
            b.other = a
            return a to b
        }
    }

    override suspend fun start() {
        while (queued.isNotEmpty()) {
            queued.removeFirstOrNull()?.let { _onMessage.invoke(it) }
        }
    }

    override suspend fun close() {
        val peer = other
        other = null
        peer?.close()
        invokeOnCloseCallback()
    }

    override suspend fun send(message: JSONRPCMessage, options: TransportSendOptions?) {
        val peer = checkNotNull(other) { "Transport is not connected" }
        peer._onMessage.invoke(message)
    }
}
