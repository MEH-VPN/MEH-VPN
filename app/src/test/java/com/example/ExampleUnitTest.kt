package com.example

import com.example.model.V2RayConfigParser
import com.example.model.V2RayProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExampleUnitTest {
  @Test
  fun parseVlessUri_parsesHostPortAndRemarks() {
    val uri =
      "vless://11111111-2222-3333-4444-555555555555@de1.example.org:443?encryption=none&security=tls&sni=de1.example.org&type=ws&path=%2Fws#Germany%20Fast"
    val parsed = V2RayConfigParser.parseSingleUri(uri)
    assertNotNull(parsed)
    assertEquals(V2RayProtocol.VLESS, parsed?.protocol)
    assertEquals("de1.example.org", parsed?.address)
    assertEquals(443, parsed?.port)
    assertEquals("Germany Fast", parsed?.remarks)
  }

  @Test
  fun parseSubscriptionContent_deduplicatesAndParsesMixedConfigs() {
    val rawList =
      """
      vless://abcdef12-3456-7890-abcd-ef1234567890@nl.server.net:8443?security=tls&type=tcp#Netherlands
      trojan://mysecretpass@fi.server.net:443?security=tls&sni=fi.server.net#Finland
      vless://abcdef12-3456-7890-abcd-ef1234567890@nl.server.net:8443?security=tls&type=tcp#DuplicateNL
      """.trimIndent()

    val configs = V2RayConfigParser.parseSubscriptionContent(rawList)
    assertEquals(2, configs.size)
    assertTrue(configs.any { it.protocol == V2RayProtocol.VLESS && it.address == "nl.server.net" })
    assertTrue(configs.any { it.protocol == V2RayProtocol.TROJAN && it.address == "fi.server.net" })
  }
}
