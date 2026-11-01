package com.example

import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfigParser
import com.example.model.V2RayProtocol
import com.example.vpn.LocalV2RayProxyServer
import com.example.vpn.V2RayOutboundClient
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request
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

  @Test
  fun parseHtmlEscapedAndEarlyDataPath_cleansPathAndFiltersUnsupportedConfigs() {
    val htmlEscapedWsUri =
      "vless://11111111-2222-3333-4444-555555555555@cdn.example.org:443?encryption=none&amp;security=tls&amp;sni=sni.example.org&amp;type=ws&amp;host=sni.example.org&amp;path=%2Fws-path%3Fed%3D2048#CleanWS"
    val parsed = V2RayConfigParser.parseSingleUri(htmlEscapedWsUri)
    assertNotNull(parsed)
    assertEquals("ws", parsed?.network)
    assertEquals("tls", parsed?.security)
    assertEquals("sni.example.org", parsed?.sni)
    assertEquals("/ws-path", parsed?.path)
    assertTrue(parsed != null && V2RayOutboundClient.isSupportedByEngine(parsed))

    val pqEncryptedUri =
      "vless://11111111-2222-3333-4444-555555555555@pq.example.org:443?encryption=mlkem768x25519plus.native.0rtt&security=tls&type=tcp#PQ"
    val pqParsed = V2RayConfigParser.parseSingleUri(pqEncryptedUri)
    assertNotNull(pqParsed)
    assertEquals(false, pqParsed != null && V2RayOutboundClient.isSupportedByEngine(pqParsed))
  }

  @Test
  fun verifyEndToEndHttpsAndSocks5DnsThroughSelectedPool() = runBlocking {
    val repo = SoliSpiritRepository()
    val configs = repo.fetchConfigsFromSoliSpirit {}
    assertTrue("Expected non-empty SoliSpirit configs", configs.isNotEmpty())

    val candidates = repo.testAndSelectFastestCandidates(configs, maxCount = 6) {}
    assertTrue("Expected verified HTTPS candidates", candidates.isNotEmpty())

    val proxy = LocalV2RayProxyServer(configs = candidates, protector = { true })
    val port = proxy.start()
    try {
      // 1. Test SOCKS5 UDP ASSOCIATE + DNS resolution for youtube.com
      Socket("127.0.0.1", port).use { ctrl ->
        ctrl.soTimeout = 6000
        val out = ctrl.getOutputStream()
        val inp = ctrl.getInputStream()
        out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
        val greet = ByteArray(2)
        assertEquals(2, inp.read(greet))
        // Send UDP ASSOCIATE (0x03)
        out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        out.flush()
        val assocReply = ByteArray(10)
        assertEquals(10, inp.read(assocReply))
        assertEquals(0x00, assocReply[1].toInt())
        val udpPort = ((assocReply[8].toInt() and 0xFF) shl 8) or (assocReply[9].toInt() and 0xFF)

        DatagramSocket().use { udpSock ->
          udpSock.soTimeout = 6000
          // SOCKS5 UDP header to 8.8.8.8:53 + DNS query for youtube.com
          val socksUdpDns =
            byteArrayOf(
              0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35,
              0x42, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              7, 'y'.code.toByte(), 'o'.code.toByte(), 'u'.code.toByte(), 't'.code.toByte(), 'u'.code.toByte(), 'b'.code.toByte(), 'e'.code.toByte(),
              3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0,
              0x00, 0x01, 0x00, 0x01,
            )
          udpSock.send(DatagramPacket(socksUdpDns, socksUdpDns.size, InetAddress.getByName("127.0.0.1"), udpPort))
          val recvBuf = ByteArray(1024)
          val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
          udpSock.receive(recvPkt)
          assertTrue("Expected valid SOCKS5 UDP DNS reply", recvPkt.length > 22)
          assertEquals(0x42, recvBuf[10].toInt() and 0xFF)
          assertEquals(0x42, recvBuf[11].toInt() and 0xFF)
        }
      }

      // 2. Test full HTTPS page fetch (https://www.google.com/generate_204 and https://www.youtube.com) over SOCKS5
      val client =
        OkHttpClient.Builder()
          .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
          .connectTimeout(8, TimeUnit.SECONDS)
          .readTimeout(8, TimeUnit.SECONDS)
          .build()

      client.newCall(Request.Builder().url("https://www.google.com/generate_204").build()).execute().use { resp ->
        assertEquals(204, resp.code)
      }

      client.newCall(Request.Builder().url("https://www.youtube.com").build()).execute().use { resp ->
        assertEquals(200, resp.code)
        val body = resp.body?.string().orEmpty()
        assertTrue(body.isNotEmpty())
      }
    } finally {
      proxy.stop()
    }
  }
}
