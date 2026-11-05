package org.umbral.core.vpn

import android.content.Context
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.umbral.core.i2p.I2pdConfigBuilder
import org.umbral.core.model.I2pConfig
import org.umbral.core.model.ModuleState
import java.io.File

/**
 * Runs the bundled i2pd router (Purple I2P, BSD-3-Clause; upstream release
 * i2pd-android 3.0.0 binaries, API 23+) as a child process.
 *
 * Mechanics: the per-ABI executables are shipped as jniLibs (libi2pd.so) and
 * extracted by the package manager into nativeLibraryDir with the executable
 * bit set (android:extractNativeLibs="true"), then exec'd via ProcessBuilder
 * — the same technique the upstream i2pd-android app uses.
 */
class I2pdController(
    private val context: Context,
    private val scope: CoroutineScope,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    data class I2pState(
        val router: ModuleState = ModuleState.OFF,
        val socksReady: Boolean = false,
        val log: List<String> = emptyList()
    )

    private val _state = MutableStateFlow(I2pState())
    val state = _state.asStateFlow()

    private var process: Process? = null
    private val logBuf = ArrayDeque<String>()
    private var cfg: I2pConfig = I2pConfig()

    fun start(cfg: I2pConfig) {
        if (_state.value.router == ModuleState.STARTING || _state.value.router == ModuleState.ACTIVE) return
        this.cfg = cfg
        val bin = binaryPath()
        if (bin == null) {
            appendLog("libi2pd.so not found in nativeLibraryDir for this ABI")
            _state.value = _state.value.copy(router = ModuleState.ERROR)
            return
        }
        try {
            val home = File(context.filesDir, "i2pd").apply { mkdirs() }
            val conf = File(home, "i2pd.conf")
            conf.writeText(I2pdConfigBuilder.build(cfg, home.absolutePath))

            val p = ProcessBuilder(
                bin.absolutePath,
                "--conf=${conf.absolutePath}",
                "--datadir=${home.absolutePath}",
                "--service"
            )
                .redirectErrorStream(true)
                .directory(home)
                .start()
            process = p
            _state.value = _state.value.copy(router = ModuleState.STARTING)
            Thread {
                runCatching {
                    p.inputStream.bufferedReader().forEachLine { appendLog(it.take(300)) }
                }
                appendLog("i2pd exited with code ${p.exitValue()}")
                _state.value = _state.value.copy(router = ModuleState.ERROR, socksReady = false)
            }.apply { isDaemon = true; name = "umbral-i2pd-log"; start() }

            scope.launch(Dispatchers.IO) {
                while (isActive) {
                    val up = probeSocks(cfg.socksPort)
                    _state.value = _state.value.copy(
                        socksReady = up,
                        router = if (up) ModuleState.ACTIVE
                        else if (_state.value.router == ModuleState.ERROR) ModuleState.ERROR
                        else ModuleState.STARTING
                    )
                    if (!up && process?.isAlive != true) break
                    delay(1000)
                }
            }
        } catch (e: Exception) {
            appendLog("start failed: ${e.message}")
            _state.value = _state.value.copy(router = ModuleState.ERROR)
        }
    }

    fun stop() {
        runCatching { process?.destroy() }
        val p = process
        process = null
        if (p != null) {
            Thread {
                runCatching { p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) }
                runCatching { p.destroyForcibly() }
            }.start()
        }
        _state.value = I2pState(router = ModuleState.STOPPING, log = logBuf.toList())
    }

    fun isSocksReady(): Boolean = _state.value.socksReady

    fun socksPort(): Int = cfg.socksPort

    private fun binaryPath(): File? =
        context.applicationInfo.nativeLibraryDir?.let { dir ->
            File(dir, "libi2pd.so").takeIf { it.canExecute() }
        }

    private fun probeSocks(port: Int): Boolean = runCatching {
        java.net.Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 1500
            s.getOutputStream().apply { write(byteArrayOf(5, 1, 0)); flush() }
            val a = s.getInputStream().read()
            val b = s.getInputStream().read()
            a == 5 && b == 0
        }
    }.getOrDefault(false)

    private fun appendLog(s: String) {
        synchronized(logBuf) {
            logBuf.addLast("${clock()} $s")
            while (logBuf.size > 300) logBuf.removeFirst()
        }
        _state.value = _state.value.copy(log = logBuf.toList())
    }
}
