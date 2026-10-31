package com.meh.vpn

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.meh.vpn.data.V2RayParser
import com.meh.vpn.model.V2RayProtocol
import com.meh.vpn.vpn.V2RayOutboundClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
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

    @Test
    fun `dead node blacklisting and dns anti poisoning filter work accurately`() {
        V2RayOutboundClient.clearBlacklist()
        val sampleUri =
            "vless://8a4f2d10-9e73-4b88-a119-6c4d5e9f0011@1.1.1.1:443?encryption=none&security=tls&sni=cloudflare.com&type=ws&path=%2Fws#DE%20Frankfurt%20Edge"
        val cfg = V2RayParser.parseSingleUri(sampleUri, "SoliSpirit/v2ray-configs")!!
        assertFalse(V2RayOutboundClient.isNodeBlacklisted(cfg))
        V2RayOutboundClient.markNodeDead(cfg)
        assertTrue(V2RayOutboundClient.isNodeBlacklisted(cfg))
        V2RayOutboundClient.clearBlacklist()
        assertFalse(V2RayOutboundClient.isNodeBlacklisted(cfg))

        // Iranian ISP sinkhole IPs must be rejected
        assertTrue(V2RayOutboundClient.isPoisonedOrPrivateIp("10.10.34.35"))
        assertTrue(V2RayOutboundClient.isPoisonedOrPrivateIp("10.10.34.36"))
        assertTrue(V2RayOutboundClient.isPoisonedOrPrivateIp("127.0.0.1"))
        assertFalse(V2RayOutboundClient.isPoisonedOrPrivateIp("104.16.132.229"))
    }

    @Test
    fun `tls clientHello probe and instant cancel work accurately`() {
        val probe = V2RayOutboundClient.buildTlsClientHelloProbe("www.youtube.com")
        assertTrue(probe.size > 60)
        assertEquals(0x16.toByte(), probe[0])
        assertEquals(0x03.toByte(), probe[1])
        assertEquals(0x01.toByte(), probe[5])
        assertTrue(String(probe, Charsets.ISO_8859_1).contains("www.youtube.com"))

        val app = ApplicationProvider.getApplicationContext<android.app.Application>()
        val vm = com.meh.vpn.ui.VpnViewModel(app)
        assertTrue(com.meh.vpn.ui.VpnViewModel.MAX_TOTAL_TESTS in 10..20)
        vm.cancelScanAndReset()
        assertEquals(com.meh.vpn.model.ConnectionStage.DISCONNECTED, vm.uiState.value.stage)
        assertEquals(0, vm.uiState.value.progressPercent)

        // Ensure remarks containing 'ist' (like SubList) are NOT falsely labeled as Turkey (TR)
        val nonTrUri = "vless://8a4f2d10-9e73-4b88-a119-6c4d5e9f0011@1.1.1.1:443?security=tls&type=ws#Fast-SubList-Node"
        val parsedNonTr = V2RayParser.parseSingleUri(nonTrUri, "SoliSpirit/v2ray-configs")
        assertNotNull(parsedNonTr)
        assertFalse(parsedNonTr!!.countryCode == "TR")
    }

    @Test
    fun `mainActivity launches without crashing`() {
        val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        assertNotNull(controller.get())
    }
}
