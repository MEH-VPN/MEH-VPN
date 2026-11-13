package com.example

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import com.example.ui.MehPhase
import com.example.ui.MehUiState
import com.example.ui.MehViewModel
import com.example.ui.theme.MyApplicationTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

  @get:Rule val composeTestRule = createComposeRule()

  @Test
  fun minimalScreen_displaysPowerButtonLiveLogAndHackerTerminalLines() {
    var clicked = false
    val sampleTerminalLogs =
      listOf(
        com.example.ui.HackerLogEntry(
          id = 1L,
          timestamp = "12:00:01",
          tag = "GIT",
          message = "اتصال به مخازن SoliSpirit و MohammadBahemmat/V2ray-Collector ...",
          level = com.example.ui.HackerLogLevel.SOURCE,
        ),
        com.example.ui.HackerLogEntry(
          id = 2L,
          timestamp = "12:00:02",
          tag = "PASS",
          message = "نود تایید شد: VLESS • پینگ 95ms",
          level = com.example.ui.HackerLogLevel.SUCCESS,
        ),
      )

    composeTestRule.setContent {
      MyApplicationTheme {
        MehMinimalScreen(
          uiState =
            MehUiState(
              phase = MehPhase.FETCHING_CONFIGS,
              liveLogLine = MehViewModel.LOG_FETCHING,
              terminalLogs = sampleTerminalLogs,
            ),
          onPowerToggle = { clicked = true },
        )
      }
    }

    composeTestRule.onNodeWithTag("vpn_toggle_button").assertIsDisplayed()
    composeTestRule.onNodeWithTag("live_status_log_container").assertIsDisplayed()
    composeTestRule.onNodeWithTag("live_status_log").assertIsDisplayed()
    composeTestRule.onNodeWithTag("minimal_sub_logs_list").assertIsDisplayed()
    composeTestRule.onNodeWithTag("vpn_toggle_button").performClick()
    assertTrue(clicked)

    // Verify rzashakeri/v2ray-configs is Priority #1 and fallback sources are registered
    assertTrue(
      "Expected rzashakeri/v2ray-configs to be Priority #1 in SOLISPIRIT_SOURCES",
      com.example.data.SoliSpiritRepository.SOLISPIRIT_SOURCES.first().url.contains("rzashakeri/v2ray-configs"),
    )
    assertTrue(
      "Expected PRIMARY_RZASHAKERI_SOURCES to be registered",
      com.example.data.SoliSpiritRepository.PRIMARY_RZASHAKERI_SOURCES.all {
        it.url.contains("rzashakeri/v2ray-configs")
      },
    )
    assertTrue(
      "Expected MohammadBahemmat/V2ray-Collector sources to be registered in fallback",
      com.example.data.SoliSpiritRepository.FALLBACK_SOURCES.any {
        it.url.contains("MohammadBahemmat/V2ray-Collector")
      },
    )
  }

  @Test
  fun telemetry_initializesAndTracksActiveUsersAndFlushesErrors() {
    val context = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()

    // 2. Verify MehTelemetry initialization & active user tracking
    com.example.telemetry.MehTelemetry.initialize(context)
    com.example.telemetry.MehTelemetry.logAppOpen("MehMinimalScreen")

    val diagAfterOpen = com.example.telemetry.MehTelemetry.getDiagnostics()
    assertTrue("Telemetry should be initialized", diagAfterOpen.isTelemetryInitialized)
    assertTrue("Client user ID must be generated and persisted", diagAfterOpen.clientUserId.startsWith("meh_"))
    assertTrue("Active session count must increment", diagAfterOpen.activeSessionsCount >= 1)
    assertTrue(
      "Should record app_open and user_active_session events",
      diagAfterOpen.recentEvents.any { it.name == "app_open" } &&
        diagAfterOpen.recentEvents.any { it.name == "user_active_session" },
    )

    // 3. Log a pre-connection error and a simulated crash error while disconnected; verify persistence & flush on connect
    com.example.telemetry.MehTelemetry.logConnectAttempt()
    com.example.telemetry.MehTelemetry.logError(
      stage = "fetch_configs",
      errorMessage = "Simulated network timeout before VPN connect",
    )
    com.example.telemetry.MehTelemetry.logError(
      stage = "uncaught_crash",
      errorMessage = "IllegalStateException: Simulated crash",
      persistSynchronously = true,
    )

    val diagBeforeConnect = com.example.telemetry.MehTelemetry.getDiagnostics()
    assertTrue("Total errors logged must be >= 2", diagBeforeConnect.totalErrorsLogged >= 2)
    assertTrue("Pre-connection errors must be buffered for flush", diagBeforeConnect.pendingBufferedErrorsCount >= 2)

    // 4. Simulate VPN connection -> should flush buffered errors and record vpn_connected + heartbeat
    com.example.telemetry.MehTelemetry.logServerConnected(
      protocol = "V2Ray:VLESS",
      serverName = "Germany-Fast",
      latencyMs = 115L,
    )
    com.example.telemetry.MehTelemetry.logActiveSessionHeartbeat(
      serverName = "Germany-Fast",
      protocol = "VLESS",
      latencyMs = 110L,
      uptimeSeconds = 60L,
    )

    val diagAfterConnect = com.example.telemetry.MehTelemetry.getDiagnostics()
    org.junit.Assert.assertEquals("connected", diagAfterConnect.lastVpnStatus)
    org.junit.Assert.assertEquals("Buffered errors should be flushed upon VPN connection", 0, diagAfterConnect.pendingBufferedErrorsCount)
    assertTrue(
      "Should emit app_error_flushed and app_crash_recovered when flushed",
      diagAfterConnect.recentEvents.any { it.name == "app_error_flushed" } &&
        diagAfterConnect.recentEvents.any { it.name == "app_crash_recovered" } &&
        diagAfterConnect.recentEvents.any { it.name == "vpn_active_heartbeat" },
    )
  }

  @Test
  fun minimalScreen_displaysConnectLastServerOptionWhenAvailable() {
    var defaultPowerClicked = false
    var connectLastClicked = false
    val sampleLastConfig =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@de1.example.org:443?encryption=none&security=tls&sni=de1.example.org&type=ws&path=%2Fws#Germany%20Fast"
      )

    composeTestRule.setContent {
      MyApplicationTheme {
        MehMinimalScreen(
          uiState =
            MehUiState(
              phase = MehPhase.DISCONNECTED,
              lastConnectedConfig = sampleLastConfig,
            ),
          onPowerToggle = { defaultPowerClicked = true },
          onConnectLastServer = { connectLastClicked = true },
        )
      }
    }

    composeTestRule.onNodeWithTag("vpn_toggle_button").assertIsDisplayed()
    composeTestRule.onNodeWithTag("connect_last_server_button").assertIsDisplayed()

    composeTestRule.onNodeWithTag("connect_last_server_button").performClick()
    assertTrue(connectLastClicked)
    org.junit.Assert.assertFalse(defaultPowerClicked)

    composeTestRule.onNodeWithTag("vpn_toggle_button").performClick()
    assertTrue(defaultPowerClicked)
  }

  @Test
  fun mehDiagAndIranRoutingAndFailover_workCorrectly() {
    // 1. Verify MehDiag counters and active traffic tracking
    com.example.vpn.MehDiag.reset()
    com.example.vpn.MehDiag.recordDnsQueryStart()
    com.example.vpn.MehDiag.recordDnsIranDirectHit(4L)
    com.example.vpn.MehDiag.recordPrewarmedPoolHit()
    com.example.vpn.MehDiag.recordFirstByteTimeoutFailover()
    com.example.vpn.MehDiag.recordIranDirectBypass()
    com.example.vpn.MehDiag.recordUdpVlessRelayedPacket()
    com.example.vpn.MehDiag.recordTlsStrictVerified()
    com.example.vpn.MehDiag.recordBytesDownloaded(8192L)

    val snap = com.example.vpn.MehDiag.snapshot()
    org.junit.Assert.assertEquals(1L, snap.dnsQueriesTotal)
    org.junit.Assert.assertEquals(1L, snap.dnsIranDirectHits)
    org.junit.Assert.assertEquals(1L, snap.prewarmedPoolHits)
    org.junit.Assert.assertEquals(1L, snap.firstByteTimeoutFailovers)
    org.junit.Assert.assertEquals(1L, snap.iranDirectBypassCount)
    org.junit.Assert.assertEquals(1L, snap.udpVlessRelayedPackets)
    org.junit.Assert.assertEquals(1L, snap.tlsStrictVerifiedCount)
    assertTrue(com.example.vpn.MehDiag.hasRecentDownloadTraffic(5_000L))

    // 2. Verify Iranian Direct Split-Tunneling rules (.ir, banking, domestic services, and Iranian CIDRs)
    assertTrue(com.example.vpn.IranRoutingRules.isIranianDestination("shaparak.ir"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianDestination("ebank.bmi.ir"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianDestination("api.digikala.com"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianDestination("torob.com"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianIpv4("2.144.12.34"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianIpv4("5.200.40.10"))
    assertTrue(com.example.vpn.IranRoutingRules.isIranianIpv4("185.143.233.5"))

    org.junit.Assert.assertFalse(com.example.vpn.IranRoutingRules.isIranianDestination("i.instagram.com"))
    org.junit.Assert.assertFalse(com.example.vpn.IranRoutingRules.isIranianDestination("api.x.com"))
    org.junit.Assert.assertFalse(com.example.vpn.IranRoutingRules.isIranianIpv4("8.8.8.8"))
    org.junit.Assert.assertFalse(com.example.vpn.IranRoutingRules.isIranianIpv4("104.16.132.229"))

    // 3. Verify mid-stream / keep-alive node failover rotation on LocalV2RayProxyServer
    val cfg1 =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@node1.example.org:443?encryption=none&security=tls&sni=node1.example.org&type=ws&path=%2Fws#Node1"
      )!!
    val cfg2 =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@node2.example.org:443?encryption=none&security=tls&sni=node2.example.org&type=ws&path=%2Fws#Node2"
      )!!
    val server = com.example.vpn.LocalV2RayProxyServer(listOf(cfg1, cfg2), protector = { true })
    org.junit.Assert.assertEquals("node1.example.org", server.activeConfig.address)
    val switched = server.switchToNextHealthyNode("keep_alive_timeout")
    org.junit.Assert.assertEquals("node2.example.org", switched.address)
    org.junit.Assert.assertEquals("node2.example.org", server.activeConfig.address)
    server.stop()

    // 4. Verify Smart Strict-First SSLContext creation
    val smartSsl = com.example.vpn.V2RayOutboundClient.createSmartSslContext("www.google.com", allowInsecureFallback = true)
    org.junit.Assert.assertNotNull(smartSsl)
  }

  @Test
  fun replaceServerPool_swapsActiveNodeAndKeepsOrder() {
    fun cfg(n: Int) =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@node$n.example.org:443?encryption=none&security=tls&sni=node$n.example.org&type=ws&path=%2Fws#Node$n"
      )!!
    val server = com.example.vpn.LocalV2RayProxyServer(listOf(cfg(1), cfg(2)), protector = { true })
    org.junit.Assert.assertEquals("node1.example.org", server.activeConfig.address)

    val newActive = server.replaceServerPool(listOf(cfg(3), cfg(1), cfg(3)))

    org.junit.Assert.assertEquals("node3.example.org", newActive.address)
    org.junit.Assert.assertEquals("node3.example.org", server.activeConfig.address)
    // duplicates removed, order kept (best first)
    org.junit.Assert.assertEquals(
      listOf("node3.example.org", "node1.example.org"),
      server.currentPool().map { it.address },
    )
    // an empty replacement is ignored
    org.junit.Assert.assertEquals("node3.example.org", server.replaceServerPool(emptyList()).address)
    server.stop()
  }
  @Test
  fun appendToServerPool_keepsActiveNodeAndDeduplicates() {
    fun cfg(n: Int) =
    com.example.model.V2RayConfigParser.parseSingleUri(
      "vless://11111111-2222-3333-4444-555555555555@node$n.example.org:443?encryption=none&security=tls&sni=node$n.example.org&type=ws&path=%2Fws#Node$n",
      )!!
    val server = com.example.vpn.LocalV2RayProxyServer(listOf(cfg(1), cfg(2)), protector = { true })
    org.junit.Assert.assertEquals("node1.example.org", server.activeConfig.address)
    val size = server.appendToServerPool(listOf(cfg(3), cfg(4), cfg(2), cfg(3)))
    org.junit.Assert.assertEquals(4, size)
    org.junit.Assert.assertEquals("node1.example.org", server.activeConfig.address)
    // duplicates removed, new nodes appended after the current pool
    org.junit.Assert.assertEquals(
      listOf("node1.example.org", "node2.example.org", "node3.example.org", "node4.example.org"),
      server.currentPool().map { it.address },
      )
    // an empty append changes nothing
    org.junit.Assert.assertEquals(4, server.appendToServerPool(emptyList()))
    org.junit.Assert.assertEquals("node1.example.org", server.activeConfig.address)
    server.stop()
  }

  @Test
  fun allNewProtocolsAndTransports_parseAndAreSupportedByEngine() {
    val vmessJson =
      """{"v":"2","ps":"VMess-WS","add":"vmess.example.org","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","type":"none","host":"vmess.example.org","path":"/vmess","tls":"tls","sni":"vmess.example.org"}"""
    val vmessUri =
      "vmess://" +
        java.util.Base64.getEncoder().encodeToString(vmessJson.toByteArray(Charsets.UTF_8))

    val ssUserInfoB64 =
      java.util.Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString("chacha20-ietf-poly1305:mySecretPass123".toByteArray(Charsets.UTF_8))
    val ssUri = "ss://$ssUserInfoB64@ss.example.org:8388#Shadowsocks-ChaCha"

    val ss2022KeyB64 =
      java.util.Base64.getEncoder().encodeToString(ByteArray(16) { (it + 1).toByte() })
    val ss2022Uri = "ss://2022-blake3-aes-128-gcm:$ss2022KeyB64@ss2022.example.org:8388#SS2022"

    val realityPubKeyB64 =
      java.util.Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(ByteArray(32) { (it + 5).toByte() })
    val realityVisionUri =
      "vless://11111111-2222-3333-4444-555555555555@reality.example.org:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$realityPubKeyB64&sid=1a2b3c4d&type=tcp#Reality-Vision"

    val tcpHttpObfsUri =
      "vless://11111111-2222-3333-4444-555555555555@mci.example.org:8080?encryption=none&security=none&type=tcp&headerType=http&host=speedtest.net&path=%2F#TCP-HTTP-Obfs"

    val grpcUri =
      "vless://11111111-2222-3333-4444-555555555555@grpc.example.org:443?encryption=none&security=tls&sni=grpc.example.org&type=grpc&serviceName=GunService#VLESS-gRPC"

    val xhttpUri =
      "vless://11111111-2222-3333-4444-555555555555@xhttp.example.org:443?encryption=none&security=tls&sni=xhttp.example.org&type=xhttp&path=%2Fsplit#VLESS-XHTTP"

    val h2Uri =
      "trojan://trojanPass123@h2.example.org:443?security=tls&sni=h2.example.org&type=h2&path=%2Fh2path#Trojan-H2"

    val kcpUri =
      "vless://11111111-2222-3333-4444-555555555555@kcp.example.org:2083?encryption=none&security=none&type=kcp&seed=mykcpseed#VLESS-mKCP"

    val hy2Uri =
      "hy2://hy2SecretAuth@hy2.example.org:443?sni=hy2.example.org&obfs=salamander&obfs-password=salamanderPass#Hysteria2"

    val tuicUri =
      "tuic://11111111-2222-3333-4444-555555555555:tuicPass@tuic.example.org:443?sni=tuic.example.org&alpn=h3#TUICv5"

    val wgPrivB64 =
      java.util.Base64.getEncoder().encodeToString(ByteArray(32) { (it + 11).toByte() })
    val wgPubB64 =
      java.util.Base64.getEncoder().encodeToString(ByteArray(32) { (it + 21).toByte() })
    val wgUri =
      "wg://$wgPrivB64@162.159.192.1:2408?publicKey=$wgPubB64&address=172.16.0.2/32&reserved=12,34,56#Warp-WG"

    val socksUri = "socks5://user1:pass1@socks.example.org:1080#Direct-SOCKS5"
    val httpProxyUri = "http://user1:pass1@proxy.example.org:8080#Direct-HTTP-Proxy"

    val uris =
      listOf(
        vmessUri,
        realityVisionUri,
        tcpHttpObfsUri,
        grpcUri,
        xhttpUri,
        h2Uri,
        kcpUri,
        hy2Uri,
        tuicUri,
        wgUri,
        socksUri,
        httpProxyUri,
      )

    for (uri in uris) {
      val parsed = com.example.model.V2RayConfigParser.parseSingleUri(uri)
      org.junit.Assert.assertNotNull("Failed to parse URI: $uri", parsed)
      assertTrue(
        "Expected engine support for ${parsed!!.protocol} (${parsed.network}/${parsed.security}): $uri",
        com.example.vpn.V2RayOutboundClient.isSupportedByEngine(parsed),
      )
    }
    // Shadowsocks is temporarily excluded (test).
    for (ss in listOf(ssUri, ss2022Uri)) {
      val parsed = com.example.model.V2RayConfigParser.parseSingleUri(ss)
      org.junit.Assert.assertNotNull("Failed to parse URI: $ss", parsed)
      org.junit.Assert.assertFalse("Shadowsocks is temporarily excluded: $ss", com.example.vpn.V2RayOutboundClient.isSupportedByEngine(parsed!!))
    }

    // Verify ChaCha20-Poly1305 & X25519 & TCP HTTP Obfuscation primitives
    val key32 = ByteArray(32) { it.toByte() }
    val nonce12 = ByteArray(12) { (it + 1).toByte() }
    val msg = "meh-vpn-protocol-test".toByteArray(Charsets.UTF_8)
    val sealed = com.example.vpn.ChaCha20Poly1305Pure.encrypt(key32, nonce12, msg, ByteArray(0))
    val opened = com.example.vpn.ChaCha20Poly1305Pure.decrypt(key32, nonce12, sealed, ByteArray(0))
    org.junit.Assert.assertArrayEquals(msg, opened)

    val pub = com.example.vpn.X25519Pure.scalarMultBase(key32)
    org.junit.Assert.assertEquals(32, pub.size)
  }

  @Test
  fun nativeXrayCoreConfig_buildsValidTunFragmentAndMultiProtocolJson() {
    val vlessWsTls =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@cdn.example.org:443?encryption=none&security=tls&sni=cdn.example.org&type=ws&host=cdn.example.org&path=%2Fws#VLESS-WS"
      )!!.copy(resolvedIp = "104.16.10.20")

    val jsonStr =
      com.example.vpn.GfwKnockerXrayCore.buildXrayCoreJson(
        config = vlessWsTls,
        includeTunInbound = true,
        tunMtu = 1400,
        localSocksPort = 20808,
      )
    org.junit.Assert.assertFalse(
      "Strict Xray JSON parser rejects unknown field 'remarks'",
      jsonStr.contains("\"remarks\""),
    )
    org.junit.Assert.assertFalse(
      "Strict Xray JSON parser rejects unknown field 'tcpNoDelay'",
      jsonStr.contains("\"tcpNoDelay\""),
    )
    org.junit.Assert.assertFalse(
      "Xray-core v26 removed 'allowInsecure'",
      jsonStr.contains("\"allowInsecure\""),
    )
    val root = org.json.JSONObject(jsonStr)
    val inbounds = root.getJSONArray("inbounds")
    org.junit.Assert.assertEquals(2, inbounds.length())
    val tunInbound = inbounds.getJSONObject(0)
    org.junit.Assert.assertEquals("tun", tunInbound.getString("protocol"))
    val tunGateway = tunInbound.getJSONObject("settings").getJSONArray("gateway")
    org.junit.Assert.assertEquals(2, tunGateway.length())
    org.junit.Assert.assertEquals("10.10.14.1/24", tunGateway.getString(0))
    org.junit.Assert.assertEquals("fd00::10:10:14:1/64", tunGateway.getString(1))
    org.junit.Assert.assertEquals("socks", inbounds.getJSONObject(1).getString("protocol"))
    org.junit.Assert.assertEquals(20808, inbounds.getJSONObject(1).getInt("port"))

    val outbounds = root.getJSONArray("outbounds")
    val proxy = outbounds.getJSONObject(0)
    org.junit.Assert.assertEquals("vless", proxy.getString("protocol"))
    org.junit.Assert.assertEquals(
      "104.16.10.20",
      proxy.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"),
    )
    val stream = proxy.getJSONObject("streamSettings")
    org.junit.Assert.assertEquals("ws", stream.getString("network"))
    org.junit.Assert.assertEquals("tls", stream.getString("security"))
    org.junit.Assert.assertEquals("chrome", stream.getJSONObject("tlsSettings").getString("fingerprint"))
    org.junit.Assert.assertFalse(stream.getJSONObject("tlsSettings").has("allowInsecure"))
    org.junit.Assert.assertEquals("cdn.example.org", stream.getJSONObject("wsSettings").getString("host"))
    org.junit.Assert.assertEquals("fragment", stream.getJSONObject("sockopt").getString("dialerProxy"))

    val fragmentOutbound = outbounds.getJSONObject(1)
    org.junit.Assert.assertFalse(fragmentOutbound.getJSONObject("settings").has("domainStrategy"))
    org.junit.Assert.assertEquals(
      "UseIPv4",
      fragmentOutbound.getJSONObject("streamSettings").getJSONObject("sockopt").getString("domainStrategy"),
    )

    val rules = root.getJSONObject("routing").getJSONArray("rules")
    assertTrue(rules.toString().contains("domain:ir"))
    org.junit.Assert.assertFalse(rules.toString().contains("domain:.ir"))

    val realityPubKey =
      java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
    val realityCfg =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@rel.example.org:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=$realityPubKey&sid=ab12&type=tcp#Reality"
      )!!
    val realityRawJson =
      com.example.vpn.GfwKnockerXrayCore.buildXrayCoreJson(
        config = realityCfg,
        includeTunInbound = true,
        localSocksPort = 20809,
      )
    org.junit.Assert.assertFalse(realityRawJson.contains("\"remarks\""))
    org.junit.Assert.assertFalse(realityRawJson.contains("\"tcpNoDelay\""))
    val realityJson = org.json.JSONObject(realityRawJson)
    val realityProxy = realityJson.getJSONArray("outbounds").getJSONObject(0)
    org.junit.Assert.assertEquals(
      "reality",
      realityProxy.getJSONObject("streamSettings").getString("security"),
    )
    org.junit.Assert.assertEquals(
      "xtls-rprx-vision",
      realityProxy
        .getJSONObject("settings")
        .getJSONArray("vnext")
        .getJSONObject(0)
        .getJSONArray("users")
        .getJSONObject(0)
        .getString("flow"),
    )

    val wgPrivB64 =
      java.util.Base64.getEncoder().encodeToString(ByteArray(32) { (it + 11).toByte() })
    val wgPubB64 =
      java.util.Base64.getEncoder().encodeToString(ByteArray(32) { (it + 21).toByte() })
    val wgCfg =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "wg://$wgPrivB64@162.159.192.1:2408?publicKey=$wgPubB64&address=172.16.0.2/32&mtu=1280#WARP"
      )!!
    val wgJson =
      org.json.JSONObject(
        com.example.vpn.GfwKnockerXrayCore.buildXrayCoreJson(
          config = wgCfg,
          includeTunInbound = true,
          localSocksPort = 20810,
        )
      )
    assertTrue(
      wgJson
        .getJSONArray("outbounds")
        .getJSONObject(0)
        .getJSONObject("settings")
        .getBoolean("noKernelTun")
    )
    val serverlessCfg =
      com.example.model.V2RayConfig(
        id = "serverless_frag_a",
        protocol = com.example.model.V2RayProtocol.SERVERLESS,
        remarks = "Serverless",
        address = "1.1.1.1",
        port = 443,
        authId = "",
        rawUri = "serverless://frag_a",
        fragmentProfile = "frag_a",
      )
    val serverlessJson =
      org.json.JSONObject(
        com.example.vpn.GfwKnockerXrayCore.buildXrayCoreJson(
          config = serverlessCfg,
          includeTunInbound = false,
          localSocksPort = 20811,
        )
      )
    org.junit.Assert.assertEquals(
      "proxy",
      serverlessJson.getJSONArray("outbounds").getJSONObject(0).getString("tag"),
    )
    val hy2Cfg =
      com.example.model.V2RayConfigParser.parseSingleUri(
        "hy2://hy2SecretAuth@hy2.example.org:443?sni=hy2.example.org&obfs=salamander&obfs-password=salamanderPass#Hysteria2"
      )!!
    val hy2Raw =
      com.example.vpn.GfwKnockerXrayCore.buildXrayCoreJson(
        config = hy2Cfg,
        includeTunInbound = true,
        localSocksPort = 20812,
      )
    org.junit.Assert.assertFalse(hy2Raw.contains("\"allowInsecure\""))
    org.junit.Assert.assertEquals(
      "hysteria",
      org.json.JSONObject(hy2Raw).getJSONArray("outbounds").getJSONObject(0).getString("protocol"),
    )
    assertTrue(com.example.vpn.NativeXrayEngine.supportsNativeXray(vlessWsTls))
    assertTrue(com.example.vpn.NativeXrayEngine.supportsNativeXray(realityCfg))
    org.junit.Assert.assertFalse(
      com.example.vpn.NativeXrayEngine.supportsNativeXray(vlessWsTls.copy(network = "h2"))
    )
    org.junit.Assert.assertFalse(
      com.example.vpn.NativeXrayEngine.supportsNativeXray(realityCfg.copy(network = "ws"))
    )
    assertTrue(com.example.vpn.NativeXrayEngine.allocateLocalPort() in 1024..65535)
    com.example.vpn.MehVpnService.emitRealtimeLog(
      "کانفیگ سریع‌تر پیدا شد",
      com.example.vpn.VpnLogLevel.SUCCESS,
    )
  }
}
