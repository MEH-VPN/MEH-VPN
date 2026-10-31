package com.meh.vpn

import com.meh.vpn.data.V2RayParser
import com.meh.vpn.model.V2RayProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class ExampleUnitTest {
    @Test
    fun vlessUri_parsesHostPortAndProtocol() {
        val sampleUri =
            "vless://8a4f2d10-9e73-4b88-a119-6c4d5e9f0011@1.1.1.1:443?encryption=none&security=tls&sni=cloudflare.com&type=ws&path=%2Fws#DE%20Frankfurt%20Edge"
        val parsed = V2RayParser.parseSingleUri(sampleUri, "barry-far/V2ray-Configs")
        assertNotNull(parsed)
        assertEquals(V2RayProtocol.VLESS, parsed!!.protocol)
        assertEquals("1.1.1.1", parsed.address)
        assertEquals(443, parsed.port)
        assertEquals("ws", parsed.network)
        assertEquals("tls", parsed.tls)
        assertEquals("DE", parsed.countryCode)
    }
}
