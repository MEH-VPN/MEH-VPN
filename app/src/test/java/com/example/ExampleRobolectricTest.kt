package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.V2RayParser
import com.example.model.V2RayProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @Test
    fun `read string from context`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("MEH", appName)
    }

    @Test
    fun `vless uri parses and generates v2ray core json`() {
        val sampleUri =
            "vless://8a4f2d10-9e73-4b88-a119-6c4d5e9f0011@1.1.1.1:443?encryption=none&security=tls&sni=cloudflare.com&type=ws&path=%2Fws#DE%20Frankfurt%20Edge"
        val parsed = V2RayParser.parseSingleUri(sampleUri, "SoliSpirit/v2ray-configs")
        assertNotNull(parsed)
        assertEquals(V2RayProtocol.VLESS, parsed!!.protocol)
        assertEquals("1.1.1.1", parsed.address)
        assertEquals(443, parsed.port)

        val coreJson = parsed.toV2RayCoreJson()
        assertTrue(coreJson.contains("\"protocol\": \"vless\""))
        assertTrue(coreJson.contains("\"address\": \"1.1.1.1\""))
    }
}
