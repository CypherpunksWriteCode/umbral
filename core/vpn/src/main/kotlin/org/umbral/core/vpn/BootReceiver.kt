package org.umbral.core.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import kotlinx.coroutines.runBlocking

/** Starts the VPN after boot when the user opted in. Best effort on API 31+. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        Thread {
            try {
                val u = U.mgr(context)
                val cfg = runBlocking { u.configRepo.current() }
                if (!cfg.autoStartOnBoot) return@Thread
                if (android.net.VpnService.prepare(context) != null) return@Thread // no consent
                val i = Intent(context, PrivacyVpnService::class.java).setAction(PrivacyVpnService.ACTION_START)
                if (Build.VERSION.SDK_INT >= 26) {
                    context.startForegroundService(i)
                } else {
                    context.startService(i)
                }
            } finally {
                pending.finish()
            }
        }.start()
    }
}
