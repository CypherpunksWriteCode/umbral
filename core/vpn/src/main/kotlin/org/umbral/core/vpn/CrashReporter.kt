package org.umbral.core.vpn

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Last-crash capture for field debugging: uncaught exceptions are written to
 * a file in app-private storage and shown on the Diagnostics screen on next
 * launch. Nothing leaves the device.
 */
object CrashReporter {

    private const val MAX_REPORTS = 5
    private lateinit var dir: File

    fun install(context: Context) {
        dir = File(context.filesDir, "crashes").apply { mkdirs() }
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching { write(thread, throwable) }
            // chain to the platform handler so the process still dies visibly
            previous?.uncaughtException(thread, throwable)
        }
    }

    private fun write(thread: Thread, t: Throwable) {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val text = buildString {
            appendLine("time: $stamp")
            appendLine("thread: ${thread.name}")
            appendLine(t.stackTraceToString())
            var cause = t.cause
            while (cause != null) {
                appendLine("caused by: ${cause.stackTraceToString()}")
                cause = cause.cause
            }
        }
        File(dir, "crash-$stamp.txt").writeText(text)
        // prune
        dir.listFiles { f -> f.name.startsWith("crash-") }
            ?.sortedByDescending { it.name }
            ?.drop(MAX_REPORTS)
            ?.forEach { it.delete() }
    }

    fun reports(): List<File> =
        if (this::dir.isInitialized) {
            dir.listFiles { f -> f.name.startsWith("crash-") }?.sortedByDescending { it.name } ?: emptyList()
        } else emptyList()

    fun clear() {
        reports().forEach { it.delete() }
    }
}
