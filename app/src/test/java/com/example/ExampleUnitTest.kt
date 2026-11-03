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

  @Test
  fun testTelegramConnect() = runBlocking {
    val repo = SoliSpiritRepository()
    val configs = repo.fetchConfigsFromSoliSpirit {}
    println("TELEGRAM_TEST: fetched ${configs.size} configs")
    val candidates = repo.testAndSelectFastestCandidates(configs, maxCount = 8) {}
    println("TELEGRAM_TEST: candidates count = ${candidates.size}")
    for ((idx, c) in candidates.withIndex()) {
      println("TELEGRAM_TEST: Candidate #$idx: ${c.protocol} ${c.address}:${c.port} net=${c.network} sni=${c.sni} path=${c.path}")
      // Test direct TCP connect to Telegram DC2 over V2Ray tunnel
      val tgStatus = try {
        V2RayOutboundClient.openTunnel(
          config = c,
          targetHost = "149.154.167.50",
          targetPort = 443,
          timeoutMs = 4000,
        ).use { conn ->
          // Send Telegram unpadded MTProto handshake preamble (0xef, 0xef, 0xef, 0xef) or test raw TCP connect
          conn.outputStream.write(byteArrayOf(0xef.toByte(), 0xef.toByte(), 0xef.toByte(), 0xef.toByte()))
          conn.outputStream.flush()
          "OPENED_AND_WRITTEN_OK"
        }
      } catch (e: Exception) {
        "FAILED: ${e.javaClass.simpleName}: ${e.message}"
      }
      println("TELEGRAM_TEST: -> Telegram DC2 result: $tgStatus")
    }
  }

  @Test
  fun testGfwKnockerXrayCoreTlsRecordSplittingAndProtocols() {
    // 1. Verify TLS ClientHello Record Splitting (22, 3, 1, lenHigh, lenLow + payload) when emitTlsRecordHeaders = true
    val payload = ByteArray(240) { (it and 0xFF).toByte() }
    val tlsRecord = ByteArray(5 + payload.size)
    tlsRecord[0] = 22 // Handshake
    tlsRecord[1] = 3
    tlsRecord[2] = 1
    tlsRecord[3] = ((payload.size ushr 8) and 0xFF).toByte()
    tlsRecord[4] = (payload.size and 0xFF).toByte()
    System.arraycopy(payload, 0, tlsRecord, 5, payload.size)

    val rawOut = java.io.ByteArrayOutputStream()
    val fragOut =
      com.example.vpn.GfwKnockerXrayCore.FragmentWriterOutputStream(
        rawOut,
        com.example.vpn.GfwKnockerXrayCore.FragmentConfig(
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 10,
          lengthMax = 25,
          intervalMinMs = 0L,
          intervalMaxMs = 1L,
          emitTlsRecordHeaders = true,
        ),
      )
    fragOut.write(tlsRecord)
    val fragmentedBytes = rawOut.toByteArray()

    // Reassemble split TLS records and verify multiple records were emitted and payload matches 100%
    val reassembled = java.io.ByteArrayOutputStream()
    var pos = 0
    var recordCount = 0
    while (pos < fragmentedBytes.size) {
      assertEquals(22, fragmentedBytes[pos].toInt() and 0xFF)
      assertEquals(3, fragmentedBytes[pos + 1].toInt() and 0xFF)
      assertEquals(1, fragmentedBytes[pos + 2].toInt() and 0xFF)
      val rLen =
        ((fragmentedBytes[pos + 3].toInt() and 0xFF) shl 8) or
          (fragmentedBytes[pos + 4].toInt() and 0xFF)
      assertTrue("Each split TLS record should be <= 25 bytes, got $rLen", rLen in 1..25)
      reassembled.write(fragmentedBytes, pos + 5, rLen)
      pos += 5 + rLen
      recordCount++
    }
    assertTrue("Expected at least 10 split TLS records, got $recordCount", recordCount >= 10)
    org.junit.Assert.assertArrayEquals(payload, reassembled.toByteArray())

    // 2. Verify default TCP segment splitting preserves exact TLS record bytes across multiple TCP flushes
    val tcpRawOut = java.io.ByteArrayOutputStream()
    val tcpFragOut =
      com.example.vpn.GfwKnockerXrayCore.FragmentWriterOutputStream(
        tcpRawOut,
        com.example.vpn.GfwKnockerXrayCore.FragmentConfig.DEFAULT_TLS_HELLO,
      )
    tcpFragOut.write(tlsRecord)
    org.junit.Assert.assertArrayEquals(tlsRecord, tcpRawOut.toByteArray())

    // 3. Verify mvless:// and jvless:// and httpupgrade support in GFW-knocker/Xray-core
    val mvlessUri =
      "mvless://11111111-2222-3333-4444-555555555555@edge.example.com:443?security=tls&sni=edge.example.com&type=httpupgrade&path=%2Fupgrade#MahsaMVLESS"
    val parsedMvless = V2RayConfigParser.parseSingleUri(mvlessUri)
    assertNotNull(parsedMvless)
    assertEquals(V2RayProtocol.MVLESS, parsedMvless?.protocol)
    assertEquals(150.toByte(), com.example.vpn.GfwKnockerXrayCore.vlessWireVersionFor(parsedMvless!!.protocol))
    assertTrue(V2RayOutboundClient.isSupportedByEngine(parsedMvless))
    assertTrue(parsedMvless.toV2RayCoreJson().contains("\"dialerProxy\": \"fragment\""))
    assertTrue(parsedMvless.toV2RayCoreJson().contains("\"packets\": \"tlshello\""))
  }

  @Test
  fun testPatternihaMethodsAndCyclicFinalmask() {
    // 1. Verify Patterniha Frag-B ([0, 104, 1]) with emitTlsRecordHeaders = true starts with a 0-length TLS record
    val payload = ByteArray(250) { ((it * 7) and 0xFF).toByte() }
    val tlsRecord = ByteArray(5 + payload.size)
    tlsRecord[0] = 22
    tlsRecord[1] = 3
    tlsRecord[2] = 1
    tlsRecord[3] = ((payload.size ushr 8) and 0xFF).toByte()
    tlsRecord[4] = (payload.size and 0xFF).toByte()
    System.arraycopy(payload, 0, tlsRecord, 5, payload.size)

    val rawOutB = java.io.ByteArrayOutputStream()
    val fragOutB =
      com.example.vpn.GfwKnockerXrayCore.FragmentWriterOutputStream(
        rawOutB,
        com.example.vpn.GfwKnockerXrayCore.FragmentConfig.PATTERNIHA_FRAG_B.copy(emitTlsRecordHeaders = true),
      )
    fragOutB.write(tlsRecord)
    val bytesB = rawOutB.toByteArray()

    // First record in Frag-B must be 0-length TLS record: [22, 3, 1, 0, 0]
    assertEquals(22, bytesB[0].toInt() and 0xFF)
    assertEquals(0, bytesB[3].toInt() and 0xFF)
    assertEquals(0, bytesB[4].toInt() and 0xFF)

    // Second record in Frag-B must have length 104, third record must have length 1
    assertEquals(104, ((bytesB[8].toInt() and 0xFF) shl 8) or (bytesB[9].toInt() and 0xFF))
    val thirdHeaderPos = 5 + (5 + 104)
    assertEquals(1, ((bytesB[thirdHeaderPos + 3].toInt() and 0xFF) shl 8) or (bytesB[thirdHeaderPos + 4].toInt() and 0xFF))

    val reassembledB = java.io.ByteArrayOutputStream()
    var pos = 0
    while (pos < bytesB.size) {
      assertEquals(22, bytesB[pos].toInt() and 0xFF)
      val rLen = ((bytesB[pos + 3].toInt() and 0xFF) shl 8) or (bytesB[pos + 4].toInt() and 0xFF)
      if (rLen > 0) {
        reassembledB.write(bytesB, pos + 5, rLen)
      }
      pos += 5 + rLen
    }
    org.junit.Assert.assertArrayEquals(payload, reassembledB.toByteArray())

    // 2. Verify CluvexStudio/Aether SNI host range finder & midpoint split
    val hostBytes = "sni.cluvex-aether.org".toByteArray(Charsets.US_ASCII)
    val sniExtLen = 2 + 1 + 2 + hostBytes.size
    val extsLen = 4 + sniExtLen
    val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
    val hsLen = 4 + bodyLen
    val clientHello = java.nio.ByteBuffer.allocate(5 + hsLen)
    clientHello.put(22.toByte()).put(3.toByte()).put(1.toByte()).putShort(hsLen.toShort())
    clientHello.put(1.toByte()) // ClientHello
    clientHello.put(((bodyLen ushr 16) and 0xFF).toByte())
    clientHello.put(((bodyLen ushr 8) and 0xFF).toByte())
    clientHello.put((bodyLen and 0xFF).toByte())
    clientHello.putShort(0x0303.toShort()) // client_version
    clientHello.put(ByteArray(32)) // random
    clientHello.put(0.toByte()) // session_id len = 0
    clientHello.putShort(2.toShort()).putShort(0x1301.toShort()) // cipher_suites
    clientHello.put(1.toByte()).put(0.toByte()) // compression_methods
    clientHello.putShort(extsLen.toShort()) // extensions length
    clientHello.putShort(0x0000.toShort()) // server_name extension
    clientHello.putShort(sniExtLen.toShort())
    clientHello.putShort((1 + 2 + hostBytes.size).toShort())
    clientHello.put(0.toByte()) // host_name type
    clientHello.putShort(hostBytes.size.toShort())
    val expectedStart = clientHello.position()
    clientHello.put(hostBytes)
    val expectedEnd = clientHello.position()

    val sniRange = com.example.vpn.GfwKnockerXrayCore.findTlsSniHostRange(clientHello.array())
    assertNotNull("Expected CluvexStudio/Aether parser to locate SNI hostname range", sniRange)
    assertEquals(expectedStart, sniRange!!.first)
    assertEquals(expectedEnd, sniRange.last + 1)

    // 3. Verify WhiteDNS and CluvexStudio/Aether are registered in MehConnectionMethod
    val methodIds = com.example.data.MehConnectionMethod.entries.map { it.id }
    assertTrue(methodIds.contains("whitedns_official"))
    assertTrue(methodIds.contains("cluvex_aether"))
    assertTrue(methodIds.contains("gfw_knocker_xray"))

    // 4. Verify Patterniha Sni-Spoofing URI (127.0.0.1:40443) maps to 188.114.98.0:443 with patterniha_sni_spoof
    val sniSpoofUri =
      "vless://dffb7646-1656-427a-8187-9c056a6a5fd5@127.0.0.1:40443?encryption=none&security=tls&type=ws&host=vff67.eu.cc&path=%2Fid-dnva&sni=vff67.eu.cc&alpn=http%2F1.1&fp=chrome#Sni-Spoofing%20CF"
    val parsedSni = V2RayConfigParser.parseSingleUri(sniSpoofUri)
    assertNotNull(parsedSni)
    assertEquals("188.114.98.0", parsedSni?.address)
    assertEquals(443, parsedSni?.port)
    assertEquals("patterniha_sni_spoof", parsedSni?.fragmentProfile)

    // 5. Verify Patterniha Serverless Frag-A config and JSON generation
    val serverlessA =
      com.example.model.V2RayConfig.createPatternihaServerless(
        profileId = "patterniha_frag_a",
        remarks = "Serverless Frag-A",
      )
    assertTrue(V2RayOutboundClient.isSupportedByEngine(serverlessA))
    assertTrue(serverlessA.toV2RayCoreJson().contains("[\"6\", \"98\", \"1\"]"))

    // 6. Verify Real Public Anycast IP Coalescing for Twitter/X and Instagram + collision-free FakeIP
    assertEquals("104.244.42.129", LocalV2RayProxyServer.resolveKnownCleanPublicIpv4("api.x.com"))
    assertEquals("104.244.42.129", LocalV2RayProxyServer.resolveKnownCleanPublicIpv4("api.twitter.com"))
    assertEquals("151.101.1.140", LocalV2RayProxyServer.resolveKnownCleanPublicIpv4("pbs.twimg.com"))
    assertEquals("157.240.241.174", LocalV2RayProxyServer.resolveKnownCleanPublicIpv4("i.instagram.com"))
    assertEquals("157.240.241.63", LocalV2RayProxyServer.resolveKnownCleanPublicIpv4("scontent-fra5-1.cdninstagram.com"))

    val seenFakeIps = HashSet<String>()
    for (i in 1..300) {
      val dom = "sub-$i.custom-test-domain.org"
      val fakeIp = LocalV2RayProxyServer.allocateFakeIpForDomain(dom)
      assertTrue("Expected unique FakeIP for $dom, got duplicate $fakeIp", seenFakeIps.add(fakeIp))
      assertEquals(dom, LocalV2RayProxyServer.resolveFakeIpDomain(fakeIp))
    }

    // 7. Verify TLS ClientHello SNI extraction for destOverride: ["tls"]
    val extractedSni = com.example.vpn.GfwKnockerXrayCore.extractTlsSniHostname(clientHello.array())
    assertEquals("sni.cluvex-aether.org", extractedSni)
  }
}


