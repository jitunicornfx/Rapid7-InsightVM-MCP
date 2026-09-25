package com.jitunicornfx.insightvm.mcp.testutil

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import java.util.concurrent.atomic.AtomicLong

/**
 * A response body produced lazily, 64 KiB at a time, that counts how much of it was ever pulled.
 *
 * A `respond(ByteArray)` body is already whole in memory, so it cannot tell a client that streams
 * from one that buffers everything before its size cap runs. This one can: Ktor's channel holds only
 * about a megabyte unread, so the producer can never get far ahead of its reader, and [produced]
 * stays small exactly when the reader stops early and cancels. A buffering client drains it to the
 * end instead.
 *
 * GlobalScope because the MockEngine handler returns before the body is consumed; the producer ends
 * on its own once the reader cancels the channel or [totalBytes] have been written.
 */
class MeteredBody(
    val totalBytes: Long = 64L * 1024 * 1024,
    private val prefix: ByteArray = ByteArray(0),
    private val suffix: ByteArray = ByteArray(0),
) {
    /** Bytes the channel has accepted so far, prefix and suffix included. */
    val produced = AtomicLong()

    /** Whether no more than [kept] bytes plus normal read-ahead were pulled, i.e. the body was streamed. */
    fun wasStreamed(kept: Long): Boolean = produced.get() < kept + READ_AHEAD_ALLOWANCE

    companion object {
        /**
         * What a streaming reader may pull beyond the bytes it keeps. Each channel between producer
         * and reader holds about 1 MiB unread and the client pipeline has more than one, so a few
         * MiB of read-ahead is normal (3 MiB measured, Ktor 3.6.0). A buffering client pulls the
         * whole 64 MiB default instead, so this stays far below what it is meant to catch.
         */
        const val READ_AHEAD_ALLOWANCE = 8L * 1024 * 1024
    }

    /** A fresh channel for one response. */
    @OptIn(DelicateCoroutinesApi::class)
    fun channel(): ByteReadChannel = GlobalScope.writer(Dispatchers.IO) {
        suspend fun emit(bytes: ByteArray) {
            channel.writeFully(bytes)
            channel.flush()
            produced.addAndGet(bytes.size.toLong())
        }
        emit(prefix)
        val chunk = ByteArray(64 * 1024) { 'A'.code.toByte() }
        var remaining = totalBytes - prefix.size - suffix.size
        while (remaining > 0) {
            val next = if (remaining >= chunk.size) chunk else chunk.copyOf(remaining.toInt())
            emit(next)
            remaining -= next.size
        }
        emit(suffix)
    }.channel
}
