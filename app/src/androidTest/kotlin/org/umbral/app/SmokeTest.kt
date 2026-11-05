package org.umbral.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Smoke test: package identity. Requires an emulator/device (not runnable in this build environment). */
@RunWith(AndroidJUnit4::class)
class SmokeTest {
    @Test
    fun packageName() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("org.umbral.app.debug", ctx.packageName)
    }
}
