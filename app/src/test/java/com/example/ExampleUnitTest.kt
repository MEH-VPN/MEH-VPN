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

    // 3. Verify only the primary V2Ray method is registered in MehConnectionMethod
    val methodIds = com.example.data.MehConnectionMethod.entries.map { it.id }
    assertEquals(listOf("v2ray_solispirit"), methodIds)

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

    // 6. Verify passive real-DNS reverse record recording
    val sampleDnsResp =
      byteArrayOf(
        0x12, 0x34, 0x81.toByte(), 0x80.toByte(),
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x03, 'a'.code.toByte(), 'p'.code.toByte(), 'i'.code.toByte(),
        0x01, 'x'.code.toByte(),
        0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
        0x00,
        0x00, 0x01, 0x00, 0x01,
        0xC0.toByte(), 0x0C.toByte(),
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04,
        172.toByte(), 66.toByte(), 0, 227.toByte(),
      )
    LocalV2RayProxyServer.recordRealDnsARecords("api.x.com", sampleDnsResp)
    assertEquals("api.x.com", LocalV2RayProxyServer.lookupDomainForRealIp("172.66.0.227"))
    assertEquals("172.66.0.227", LocalV2RayProxyServer.lookupRealIpForDomain("api.x.com"))

    // 7. Verify TLS ClientHello SNI extraction for destOverride: ["tls"]
    val extractedSni = com.example.vpn.GfwKnockerXrayCore.extractTlsSniHostname(clientHello.array())
    assertEquals("sni.cluvex-aether.org", extractedSni)
  }

  @Test
  fun diagnoseInstagramAndTwitterOverTun2SocksSimulation() = runBlocking {
    val repo = SoliSpiritRepository()
    val configs = repo.fetchConfigsFromSoliSpirit {}
    println("DIAG: Fetched ${configs.size} configs for tun2socks simulation")
    val candidates = repo.testAndSelectFastestCandidates(configs, maxCount = 6) {}
    println("DIAG: Selected ${candidates.size} candidates:")
    for ((i, c) in candidates.withIndex()) {
      println("DIAG: Candidate #$i: ${c.protocol} ${c.address}:${c.port} sni=${c.sni} host=${c.hostHeader} net=${c.network} ping=${c.latencyMs}ms")
    }

    val proxy = LocalV2RayProxyServer(configs = candidates, protector = { true })
    val port = proxy.start()
    try {
      // Helper to send a real Android-style DNS query (with 11-byte EDNS0 OPT record, ARCOUNT=1)
      // through SOCKS5 UDP ASSOCIATE (cmd = 0x03) -> LocalV2RayProxyServer UDP relay -> V2Ray tunnel
      fun queryDnsViaSocks5UdpAssociate(hostname: String, qtype: Int): ByteArray {
        Socket("127.0.0.1", port).use { controlSocket ->
          controlSocket.soTimeout = 8_000
          val out = controlSocket.getOutputStream()
          val inp = java.io.DataInputStream(controlSocket.getInputStream())
          out.write(byteArrayOf(0x05, 0x01, 0x00))
          out.flush()
          val greet = ByteArray(2)
          inp.readFully(greet)
          // Send CMD = 0x03 (UDP ASSOCIATE)
          out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
          out.flush()
          val assocResp = ByteArray(10)
          inp.readFully(assocResp)
          assertEquals("SOCKS5 UDP ASSOCIATE must succeed", 0x00, assocResp[1].toInt())
          val udpRelayPort = ((assocResp[8].toInt() and 0xFF) shl 8) or (assocResp[9].toInt() and 0xFF)

          // Build DNS query with Android 9 EDNS0 OPT record (ARCOUNT = 1, 11 trailing bytes)
          val qbuf = java.io.ByteArrayOutputStream()
          qbuf.write(byteArrayOf(0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01))
          for (label in hostname.split('.')) {
            val lb = label.toByteArray(Charsets.US_ASCII)
            qbuf.write(lb.size)
            qbuf.write(lb)
          }
          qbuf.write(0x00)
          qbuf.write((qtype ushr 8) and 0xFF)
          qbuf.write(qtype and 0xFF)
          qbuf.write(0x00)
          qbuf.write(0x01)
          val questionEndOffset = qbuf.size()
          // Append 11-byte EDNS0 OPT record (root=0x00, type=41, payload=4096, rcode=0, rdlen=0)
          qbuf.write(byteArrayOf(0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
          val dnsQueryBytes = qbuf.toByteArray()

          // Wrap in SOCKS5 UDP header targeting 8.8.8.8:53
          val socks5UdpReq = ByteArray(10 + dnsQueryBytes.size)
          socks5UdpReq[3] = 0x01 // ATYP IPv4
          socks5UdpReq[4] = 8
          socks5UdpReq[5] = 8
          socks5UdpReq[6] = 8
          socks5UdpReq[7] = 8
          socks5UdpReq[8] = 0
          socks5UdpReq[9] = 53
          System.arraycopy(dnsQueryBytes, 0, socks5UdpReq, 10, dnsQueryBytes.size)

          java.net.DatagramSocket().use { udpSocket ->
            udpSocket.soTimeout = 8_000
            val pkt = java.net.DatagramPacket(
              socks5UdpReq,
              socks5UdpReq.size,
              InetAddress.getByName("127.0.0.1"),
              udpRelayPort,
            )
            udpSocket.send(pkt)
            val recvBuf = ByteArray(2048)
            val recvPkt = java.net.DatagramPacket(recvBuf, recvBuf.size)
            udpSocket.receive(recvPkt)
            assertTrue("SOCKS5 UDP reply must be > 22 bytes", recvPkt.length > 22)
            val dnsReply = recvBuf.copyOfRange(10, recvPkt.length)
            if (qtype == 28 || qtype == 65 || qtype == 64) {
              // Verify AAAA / HTTPS / SVCB empty NOERROR response has ZERO trailing EDNS0 garbage bytes!
              assertEquals(
                "Empty NOERROR response must truncate EDNS0 trailing bytes so Android libnetd_resolv ns_initparse (cp == eom) succeeds",
                questionEndOffset,
                dnsReply.size,
              )
            }
            return dnsReply
          }
        }
      }

      // Verify HTTPS/SVCB (QTYPE=65) is cleanly answered with 0-answer NOERROR
      val httpsRrReply = queryDnsViaSocks5UdpAssociate("x.com", qtype = 65)
      val httpsAnCount = ((httpsRrReply[6].toInt() and 0xFF) shl 8) or (httpsRrReply[7].toInt() and 0xFF)
      assertEquals(0, httpsAnCount)

      // Parse first IPv4 A record from raw DNS response
      fun extractFirstARecord(dnsReply: ByteArray): ByteArray? {
        if (dnsReply.size < 12) return null
        val anCount = ((dnsReply[6].toInt() and 0xFF) shl 8) or (dnsReply[7].toInt() and 0xFF)
        if (anCount <= 0) return null
        var idx = 12
        // Skip QNAME
        while (idx < dnsReply.size) {
          val len = dnsReply[idx].toInt() and 0xFF
          if (len == 0) {
            idx += 1
            break
          }
          if ((len and 0xC0) == 0xC0) {
            idx += 2
            break
          }
          idx += 1 + len
        }
        idx += 4 // QTYPE + QCLASS
        repeat(anCount) {
          if (idx >= dnsReply.size) return null
          // Skip RR NAME
          while (idx < dnsReply.size) {
            val len = dnsReply[idx].toInt() and 0xFF
            if (len == 0) {
              idx += 1
              break
            }
            if ((len and 0xC0) == 0xC0) {
              idx += 2
              break
            }
            idx += 1 + len
          }
          if (idx + 10 > dnsReply.size) return null
          val rtype = ((dnsReply[idx].toInt() and 0xFF) shl 8) or (dnsReply[idx + 1].toInt() and 0xFF)
          val rdlen = ((dnsReply[idx + 8].toInt() and 0xFF) shl 8) or (dnsReply[idx + 9].toInt() and 0xFF)
          idx += 10
          if (idx + rdlen > dnsReply.size) return null
          if (rtype == 1 && rdlen == 4) {
            return dnsReply.copyOfRange(idx, idx + 4)
          }
          idx += rdlen
        }
        return null
      }

      val customDns = object : okhttp3.Dns {
        override fun lookup(hostname: String): List<InetAddress> {
          // 1. Test Android's simultaneous AAAA query with EDNS0
          val aaaaReply = queryDnsViaSocks5UdpAssociate(hostname, qtype = 28)
          assertEquals(0, ((aaaaReply[6].toInt() and 0xFF) shl 8) or (aaaaReply[7].toInt() and 0xFF))
          // 2. Test Android's A query via SOCKS5 UDP ASSOCIATE
          val aReply = queryDnsViaSocks5UdpAssociate(hostname, qtype = 1)
          val ipv4Bytes = extractFirstARecord(aReply)
          assertNotNull("Expected valid IPv4 A record from SOCKS5 UDP DNS for $hostname", ipv4Bytes)
          val ipStr = "${ipv4Bytes!![0].toInt() and 0xFF}.${ipv4Bytes[1].toInt() and 0xFF}.${ipv4Bytes[2].toInt() and 0xFF}.${ipv4Bytes[3].toInt() and 0xFF}"
          val mappedDomain =
            LocalV2RayProxyServer.lookupSyntheticDomainForIp(ipStr)
              ?: LocalV2RayProxyServer.lookupDomainForRealIp(ipStr)
          assertNotNull("Expected IP $ipStr to map back to $hostname", mappedDomain)
          println("DIAG_UDP_DNS: $hostname -> $ipStr (mapped=$mappedDomain, replySize=${aReply.size} bytes)")
          // Return an InetAddress with EMPTY hostname so Socket.connect only sees the raw IPv4 bytes (ATYP=0x01)!
          return listOf(InetAddress.getByAddress("", ipv4Bytes))
        }
      }

      val tun2socksSocketFactory = object : javax.net.SocketFactory() {
        override fun createSocket(): Socket {
          return object : Socket() {
            override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) {
              val inetEndpoint = endpoint as InetSocketAddress
              val targetIp = inetEndpoint.address.address
              val targetPort = inetEndpoint.port
              super.connect(InetSocketAddress("127.0.0.1", port), timeout.coerceAtLeast(5000))
              this.tcpNoDelay = true
              this.soTimeout = 10_000
              val out = this.getOutputStream()
              val inp = this.getInputStream()
              out.write(byteArrayOf(0x05, 0x01, 0x00))
              out.flush()
              val greet = ByteArray(2)
              java.io.DataInputStream(inp).readFully(greet)
              val req = byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                targetIp[0], targetIp[1], targetIp[2], targetIp[3],
                ((targetPort ushr 8) and 0xFF).toByte(),
                (targetPort and 0xFF).toByte(),
              )
              out.write(req)
              out.flush()
              val resp = ByteArray(10)
              java.io.DataInputStream(inp).readFully(resp)
              if (resp[1].toInt() != 0x00) {
                throw java.io.IOException("SOCKS5 CONNECT failed with code ${resp[1]}")
              }
            }
          }
        }

        override fun createSocket(host: String, port: Int): Socket =
          createSocket().apply { connect(InetSocketAddress(host, port), 5000) }
        override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket =
          createSocket().apply { connect(InetSocketAddress(host, port), 5000) }
        override fun createSocket(host: InetAddress, port: Int): Socket =
          createSocket().apply { connect(InetSocketAddress(host, port), 5000) }
        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
          createSocket().apply { connect(InetSocketAddress(address, port), 5000) }
      }

      val client =
        OkHttpClient.Builder()
          .socketFactory(tun2socksSocketFactory)
          .dns(customDns)
          .connectTimeout(10, TimeUnit.SECONDS)
          .readTimeout(10, TimeUnit.SECONDS)
          .build()

      val urls = listOf(
        "https://www.google.com/generate_204",
        "https://www.instagram.com/",
        "https://i.instagram.com/api/v1/si/fetch_headers/",
        "https://graph.instagram.com/",
        "https://scontent.cdninstagram.com/",
        "https://x.com/",
        "https://api.x.com/1.1/help/settings.json",
        "https://api.twitter.com/1.1/help/settings.json",
        "https://abs.twimg.com/",
        "https://pbs.twimg.com/",
        "https://video.twimg.com/",
      )

      var seqSuccess = 0
      for (url in urls) {
        try {
          val start = System.currentTimeMillis()
          client.newCall(
            Request.Builder()
              .url(url)
              .header("User-Agent", "Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
              .build()
          ).execute().use { resp ->
            val bodyBytes = resp.body?.bytes() ?: ByteArray(0)
            val elapsed = System.currentTimeMillis() - start
            seqSuccess++
            println("DIAG_TUN2SOCKS_SEQ: $url -> HTTP ${resp.code} (${resp.protocol}) bytes=${bodyBytes.size} in ${elapsed}ms")
          }
        } catch (e: Exception) {
          println("DIAG_TUN2SOCKS_SEQ_FAIL: $url -> ${e.javaClass.simpleName}: ${e.message}")
        }
      }
      assertTrue("Expected at least 9 of 11 sequential Instagram/Twitter/Google URLs to succeed, got $seqSuccess", seqSuccess >= 9)

      // Now simulate scrolling Instagram feed & opening Twitter timeline: 16 CONCURRENT requests!
      println("DIAG_CONCURRENT: Launching 16 parallel requests...")
      val pool = java.util.concurrent.Executors.newFixedThreadPool(16)
      var concSuccess = 0
      val futures =
        (1..16).map { idx ->
          val targetUrl = urls[idx % urls.size]
          pool.submit<Pair<Boolean, String>> {
            try {
              val start = System.currentTimeMillis()
              client.newCall(
                Request.Builder()
                  .url(targetUrl)
                  .header("Cache-Control", "no-cache")
                  .header("User-Agent", "Instagram 312.0.0.34.111 Android (28/9; 480dpi; 1080x2076; samsung; SM-G950F; dreamlte; samsungexynos8895; fa_IR)")
                  .build()
              ).execute().use { resp ->
                val b = resp.body?.bytes() ?: ByteArray(0)
                val elapsed = System.currentTimeMillis() - start
                Pair(true, "CONC #$idx ($targetUrl) -> HTTP ${resp.code} (${resp.protocol}) bytes=${b.size} in ${elapsed}ms")
              }
            } catch (e: Exception) {
              Pair(false, "CONC_FAIL #$idx ($targetUrl) -> ${e.javaClass.simpleName}: ${e.message}")
            }
          }
        }
      for (f in futures) {
        val (ok, msg) = f.get()
        if (ok) concSuccess++
        println("DIAG_CONCURRENT: $msg")
      }
      pool.shutdownNow()
      assertTrue("Expected at least 14 of 16 concurrent Instagram/Twitter stream requests to succeed, got $concSuccess", concSuccess >= 14)
      Unit
    } finally {
      proxy.stop()
    }
  }
}



