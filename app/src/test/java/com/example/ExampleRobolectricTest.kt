package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.AetherGatewayEngine
import com.example.data.PatternihaBypassEngine
import com.example.data.V2RayParser
import com.example.model.V2RayProtocol
import org.junit.Assert.assertEquals
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
    fun `aether and patterniha serverless and sni spoofing configs build and parse cleanly`() {
        val aetherCfg = AetherGatewayEngine.buildAetherConfig(
            address = "162.159.198.1",
            port = 443,
            sni = "engage.cloudflareclient.com",
            countryCode = "DE",
            pingMs = 48
        )
        val parsedAether = V2RayParser.parseSingleUri(aetherCfg.rawUri, aetherCfg.sourceRepo)
        assertNotNull(parsedAether)
        assertEquals(V2RayProtocol.AETHER, parsedAether!!.protocol)
        assertTrue(parsedAether.toV2RayCoreJson().replace("\\/", "/").contains("CluvexStudio/Aether"))

        val serverlessCfg = PatternihaBypassEngine.buildServerlessConfig(
            address = "104.16.132.229",
            port = 443,
            sni = "cp.cloudflare.com",
            countryCode = "NL",
            pingMs = 52
        )
        val parsedServerless = V2RayParser.parseSingleUri(serverlessCfg.rawUri, serverlessCfg.sourceRepo)
        assertNotNull(parsedServerless)
        assertEquals(V2RayProtocol.SERVERLESS, parsedServerless!!.protocol)
        assertEquals("🇳🇱", parsedServerless.flagEmoji)
        assertTrue(parsedServerless.toV2RayCoreJson().replace("\\/", "/").contains("patterniha/Serverless-for-Iran"))

        val sniSpoofCfg = PatternihaBypassEngine.buildSniSpoofConfig(
            address = "172.64.155.209",
            port = 443,
            fakeSni = "speedtest.net",
            countryCode = "FI",
            pingMs = 59
        )
        val parsedSniSpoof = V2RayParser.parseSingleUri(sniSpoofCfg.rawUri, sniSpoofCfg.sourceRepo)
        assertNotNull(parsedSniSpoof)
        assertEquals(V2RayProtocol.SNI_SPOOF, parsedSniSpoof!!.protocol)
        assertEquals("🇫🇮", parsedSniSpoof.flagEmoji)
        assertTrue(parsedSniSpoof.toV2RayCoreJson().replace("\\/", "/").contains("patterniha/SNI-Spoofing"))
    }

    @Test
    fun `mainActivity launches without crashing`() {
        val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        assertNotNull(controller.get())
    }
}
