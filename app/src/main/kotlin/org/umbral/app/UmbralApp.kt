package org.umbral.app

import android.app.Application
import org.umbral.core.vpn.CrashReporter

class UmbralApp : Application() {
    override fun onCreate() {
        super.onCreate()
        CrashReporter.install(this)
    }
}
