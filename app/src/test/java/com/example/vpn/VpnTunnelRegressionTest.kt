package com.example.vpn

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.test.core.app.ApplicationProvider
import com.example.data.DeadServerStore
import com.example.data.VerifiedServerPoolStore
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Deterministic, offline regression suite protecting against every "connects but nothing loads"
 * and "Xray failed to parse json config" failure mode across future updates:
 *
 * 1. Real loopback SOCKS5 verification: proves port-80-only / TLS-broken proxies are REJECTED and
 *    only port-443 HTTPS targets (www.google.com:443 & cp.cloudflare.com:443) are probed.
 * 2. `hev-socks5-tunnel` + `mapdns` + Android `VpnService` topology contract.
 * 3. Full Xray-core v26 JSON schema & routing invariants across all supported protocols/transports.
 * 4. Safe live server hot-swap, isolated pre-verification, rollback, and port-busy restart retry.
 * 5. Smart one-shot background refinement + active-traffic protection + standby pool ordering.
 * 6. Manifest VPN service binding and native runtime class contracts (`LibXray`, `TProxyService`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class VpnTunnelRegressionTest {

  @Test
  fun socks5Verifier_probesHttps443Only_andRejectsTlsBrokenProxy() {
    val requestedTargets = CopyOnWriteArrayList<Pair<String, Int>>()
    ServerSocket(0, 16, InetAddress.getByName("127.0.0.1")).use { server ->
      server.soTimeout = 4000
      val worker =
        thread(isDaemon = true) {
          repeat(4) {
            val client =
              try {
                server.accept()
              } catch (_: Exception) {
                return@thread
              }
            try {
              client.soTimeout = 1500
              val inp = DataInputStream(client.getInputStream())
              val out = client.getOutputStream()
              val ver = inp.readUnsignedByte()
              if (ver != 0x05) return@repeat
              val nMethods = inp.readUnsignedByte()
              inp.readFully(ByteArray(nMethods))
              out.write(byteArrayOf(0x05, 0x00))
              out.flush()

              val reqVer = inp.readUnsignedByte()
              val cmd = inp.readUnsignedByte()
              inp.readUnsignedByte() // RSV
              val atyp = inp.readUnsignedByte()
              val host =
                when (atyp) {
                  0x03 -> {
                    val len = inp.readUnsignedByte()
                    val buf = ByteArray(len)
                    inp.readFully(buf)
                    String(buf, Charsets.US_ASCII)
                  }
                  0x01 -> {
                    val ip = ByteArray(4)
                    inp.readFully(ip)
                    ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
                  }
                  else -> "unknown"
                }
              val port = inp.readUnsignedShort()
              if (reqVer == 0x05 && cmd == 0x01) {
                requestedTargets.add(host to port)
              }

              // Simulate a TLS-broken proxy: accept SOCKS5 CONNECT, then immediately close on 443
              // (or return plain HTTP 204 if someone ever accidentally tries port 80).
              out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
              out.flush()
              if (port == 80) {
                out.write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                out.flush()
              }
            } catch (_: Exception) {
            } finally {
              try {
                client.close()
              } catch (_: Exception) {}
            }
          }
        }

      val result = MehVpnService.verifyRealPathOverSocks(server.localPort, timeoutMs = 1200)
      assertNull("TLS-broken SOCKS5 proxy must NEVER pass verification", result)
      worker.join(2500)
    }

    assertTrue(
      "Expected verifier to probe filtered bypass endpoints (YouTube -> Instagram -> X), saw $requestedTargets",
      requestedTargets.size >= 3,
    )
    assertTrue(
      "Verifier must probe filtered www.youtube.com:443, saw $requestedTargets",
      requestedTargets.any { it.first == "www.youtube.com" && it.second == 443 },
    )
    assertTrue(
      "Verifier must fall back to filtered i.instagram.com:443, saw $requestedTargets",
      requestedTargets.any { it.first == "i.instagram.com" && it.second == 443 },
    )
    assertTrue(
      "Verifier must fall back to filtered api.x.com:443, saw $requestedTargets",
      requestedTargets.any { it.first == "api.x.com" && it.second == 443 },
    )
    assertTrue(
      "Verifier must NOT accept unfiltered www.google.com or cp.cloudflare.com alone, saw $requestedTargets",
      requestedTargets.none { it.first == "www.google.com" || it.first == "cp.cloudflare.com" },
    )
    assertTrue(
      "Verifier must NEVER fall back to plain HTTP port 80, saw $requestedTargets",
      requestedTargets.none { it.second == 80 },
    )
  }

  @Test
  fun hevTunnelYamlAndVpnTopology_usesRealDnsWithoutMapDnsAndMatchesXraySocksContract() {
    val socksPort = 24808
    val yaml =
      GfwKnockerXrayCore.buildHevSocks5TunnelYaml(
        socksPort = socksPort,
        tunMtu = MehVpnService.TUN_MTU,
        tunIpv4 = MehVpnService.TUN_IPV4_ADDRESS,
      )

    assertEquals("10.10.14.1", MehVpnService.TUN_IPV4_ADDRESS)
    assertEquals("1.1.1.1", MehVpnService.PRIMARY_DNS_ADDRESS)
    assertEquals("8.8.8.8", MehVpnService.SECONDARY_DNS_ADDRESS)
    assertTrue(yaml.contains("mtu: ${MehVpnService.TUN_MTU}"))
    assertTrue(yaml.contains("ipv4: ${MehVpnService.TUN_IPV4_ADDRESS}"))
    assertFalse(
      "hev-socks5-tunnel MUST omit ipv6 by default so Android fails IPv6 fast and never stalls on AAAA/IPv4-only servers",
      yaml.contains("ipv6:"),
    )
    assertTrue(yaml.contains("port: $socksPort"))
    assertTrue(yaml.contains("address: 127.0.0.1"))
    assertTrue("hev-socks5-tunnel must use standard RFC1928 UDP mode for Xray", yaml.contains("udp: 'udp'"))
    assertFalse("udp: 'tcp' is unsupported by Xray socks inbound", yaml.contains("udp: 'tcp'"))
    assertFalse("Fake DNS / mapdns MUST be completely removed", yaml.contains("mapdns:"))
    assertFalse("Must NEVER allocate CGNAT fake-IP range 100.64.0.0", yaml.contains("100.64.0.0"))
    assertFalse("Avoid reserved Class E 240.0.0.0/4 on Android kernels", yaml.contains("240.0.0.0"))
    assertTrue("Must use valid hev-socks5-tunnel key read-write-timeout", yaml.contains("read-write-timeout:"))
    assertTrue("connect-timeout should allow 10s for high-latency mobile handshakes", yaml.contains("connect-timeout: 10000"))
    assertFalse("tcp-read-write-timeout is rejected by libhev-socks5-tunnel.so", yaml.contains("tcp-read-write-timeout:"))
    assertTrue(yaml.startsWith("tunnel:\n  mtu: ${MehVpnService.TUN_MTU}\n"))
  }

  @Test
  fun xrayJsonConfigs_forAllSupportedProtocols_passSchemaAndRoutingInvariants() {
    val realityPbk = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 9 })
    val vmessJson =
      """{"v":"2","ps":"VMessWS","add":"vm.example.org","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","type":"none","host":"vm.example.org","path":"/ws","tls":"tls"}"""
    val vmessUri = "vmess://${Base64.getEncoder().encodeToString(vmessJson.toByteArray())}"
    val ssCred = Base64.getEncoder().encodeToString("aes-256-gcm:StrongPass123".toByteArray())
    val wgKey = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 5 })
    val wgPub = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 6 })

    val testConfigs =
      listOf(
        V2RayConfigParser.parseSingleUri(
          "vless://11111111-2222-3333-4444-555555555555@ws.example.org:443?encryption=none&security=tls&sni=ws.example.org&type=ws&host=ws.example.org&path=%2Fws#VLESS-WS"
        )!!,
        V2RayConfigParser.parseSingleUri(
          "vless://11111111-2222-3333-4444-555555555555@rel.example.org:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=$realityPbk&sid=a1b2&type=tcp#VLESS-Reality"
        )!!,
        V2RayConfigParser.parseSingleUri(
          "vless://11111111-2222-3333-4444-555555555555@grpc.example.org:443?encryption=none&security=tls&sni=grpc.example.org&type=grpc&serviceName=gunsvc#VLESS-gRPC"
        )!!,
        V2RayConfigParser.parseSingleUri(
          "vless://11111111-2222-3333-4444-555555555555@xhttp.example.org:443?encryption=none&security=tls&sni=xhttp.example.org&type=xhttp&path=%2Fxhttp#VLESS-XHTTP"
        )!!,
        V2RayConfigParser.parseSingleUri(vmessUri)!!,
        V2RayConfigParser.parseSingleUri(
          "trojan://secretpass@tr.example.org:443?security=tls&sni=tr.example.org&type=ws&host=tr.example.org&path=%2Ftr#Trojan-WS"
        )!!,
        V2RayConfigParser.parseSingleUri(
          "trojan://secretpass@tr-http.example.org:80?security=none&type=tcp&headerType=http&host=soft98.ir&path=%2F#Trojan-HTTP-Obfs"
        )!!,
        V2RayConfigParser.parseSingleUri("ss://$ssCred@ss.example.org:8388#Shadowsocks-AEAD")!!,
        V2RayConfigParser.parseSingleUri(
          "hy2://hy2Auth@hy2.example.org:443?sni=hy2.example.org&obfs=salamander&obfs-password=salpass#Hysteria2"
        )!!,
        V2RayConfigParser.parseSingleUri(
          "wg://$wgKey@162.159.192.1:2408?publicKey=$wgPub&address=172.16.0.2/32&mtu=1280#Warp-WG"
        )!!,
        V2RayConfigParser.parseSingleUri("socks://user:pass@socks.example.org:1080#SOCKS5")!!,
        V2RayConfig.createPatternihaServerless(
          profileId = "patterniha_frag_a",
          remarks = "Serverless",
        ),
      )

    for (cfg in testConfigs) {
      assertTrue("Expected native Xray support for ${cfg.remarks}", NativeXrayEngine.supportsNativeXray(cfg))
      for (useFrag in listOf(false, true)) {
        val rawJson =
          GfwKnockerXrayCore.buildXrayCoreJson(
            config = cfg,
            includeTunInbound = false,
            tunMtu = MehVpnService.TUN_MTU,
            localSocksPort = 20808,
            useFragment = useFrag,
          )

        // Guard against previously seen Xray-core v26 `infra/conf/serial` parse errors.
        assertFalse("${cfg.remarks} must not contain unsupported 'remarks'", rawJson.contains("\"remarks\""))
        assertFalse("${cfg.remarks} must not contain unsupported 'tcpNoDelay'", rawJson.contains("\"tcpNoDelay\""))
        assertFalse("${cfg.remarks} must not contain invalid 'domain:.ir'", rawJson.contains("domain:.ir"))

        val root = JSONObject(rawJson)
        val policyLevels = root.getJSONObject("policy").getJSONObject("levels")
        val level8 = policyLevels.getJSONObject("8")
        assertTrue("Level 8 handshake timeout must be >= 8s for bursty mobile handshakes", level8.getInt("handshake") >= 8)
        assertTrue("Level 8 bufferSize must be >= 32 KB for media feeds", level8.getInt("bufferSize") >= 32)

        val inbounds = root.getJSONArray("inbounds")
        assertEquals("${cfg.remarks} live mode must only bind socks-in (hev-tunnel owns TUN)", 1, inbounds.length())
        val socksIn = inbounds.getJSONObject(0)
        assertEquals("socks-in", socksIn.getString("tag"))
        assertEquals("127.0.0.1", socksIn.getString("listen"))
        assertEquals(20808, socksIn.getInt("port"))
        assertTrue(socksIn.getJSONObject("settings").getBoolean("udp"))
        assertEquals("127.0.0.1", socksIn.getJSONObject("settings").getString("ip"))
        val sniffOverrides = socksIn.getJSONObject("sniffing").getJSONArray("destOverride")
        val sniffSet = (0 until sniffOverrides.length()).map { sniffOverrides.getString(it) }.toSet()
        assertTrue("socks-in sniffing must cover http, tls, and quic", setOf("http", "tls", "quic").all { it in sniffSet })

        val outbounds = root.getJSONArray("outbounds")
        assertEquals("proxy", outbounds.getJSONObject(0).getString("tag"))

        // Verify freedom/fragment outbounds never place domainStrategy inside settings (must be in sockopt).
        for (i in 0 until outbounds.length()) {
          val ob = outbounds.getJSONObject(i)
          if (ob.getString("protocol") == "freedom") {
            assertFalse(
              "${cfg.remarks} freedom outbound must not put domainStrategy in settings",
              ob.getJSONObject("settings").has("domainStrategy"),
            )
          }
          if (ob.getString("protocol") == "hysteria") {
            assertFalse(
              "${cfg.remarks} hysteria must not put allowInsecure in JSON",
              ob.toString().contains("\"allowInsecure\""),
            )
          }
        }

        val routing = root.getJSONObject("routing")
        assertEquals(
          "${cfg.remarks} must use AsIs routing to avoid blocking router DNS lookups",
          "AsIs",
          routing.getString("domainStrategy"),
        )
        val rules = routing.getJSONArray("rules")
        var hasQuicUdp443Block = false
        var hasDnsPort53Rule = false
        var directBypassesMapDnsPool = false
        var sinkholeBlockIdx = -1
        var privateDirectIdx = -1
        for (i in 0 until rules.length()) {
          val r = rules.getJSONObject(i)
          if (
            r.optString("network") == "udp" &&
              r.optString("port") == "443" &&
              r.optString("outboundTag") == "block"
          ) {
            hasQuicUdp443Block = true
          }
          if (r.optString("port") == "53" && r.optString("outboundTag") == "dns-out") {
            hasDnsPort53Rule = true
          }
          if (r.optString("outboundTag") == "block" && r.has("ip")) {
            val ipArr = r.getJSONArray("ip")
            val ipItems = (0 until ipArr.length()).map { ipArr.getString(it) }
            if ("10.10.34.0/24" in ipItems) {
              sinkholeBlockIdx = i
            }
          }
          if (r.optString("outboundTag") == "direct" && r.has("ip")) {
            val ipArr = r.getJSONArray("ip")
            val ipItems = (0 until ipArr.length()).map { ipArr.getString(it) }
            if ("10.0.0.0/8" in ipItems) {
              privateDirectIdx = i
            }
            if (ipItems.any { it.contains("100.64.0.0") }) {
              directBypassesMapDnsPool = true
            }
          }
        }
        assertTrue("${cfg.remarks} must block QUIC UDP:443 for Instagram/Chrome/YouTube", hasQuicUdp443Block)
        assertTrue("${cfg.remarks} must redirect port 53 to dns-out", hasDnsPort53Rule)
        assertTrue(
          "${cfg.remarks} must block Iranian DNS sinkhole 10.10.34.0/24 BEFORE 10.0.0.0/8 direct rule",
          sinkholeBlockIdx >= 0 && privateDirectIdx > sinkholeBlockIdx,
        )
        assertFalse(
          "${cfg.remarks} direct IP rule must NEVER match mapdns fake-IP range 100.64.0.0/10",
          directBypassesMapDnsPool,
        )
      }
    }
  }

  @Test
  fun safeServerSwap_neverTouchesLiveCoreOnDeadChallenger_andAlwaysRestoresOnLiveFailure() {
    val active =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@active.example.org:443?security=tls&type=ws#Active"
      )!!
    val deadChallenger =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@dead.example.org:443?security=tls&type=ws#Dead"
      )!!
    val flakyChallenger =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@flaky.example.org:443?security=tls&type=ws#Flaky"
      )!!
    val goodChallenger =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@good.example.org:443?security=tls&type=ws#Good"
      )!!

    // Case A: Dead challenger fails isolated ping -> live Xray must NEVER be touched!
    var liveLaunchCount = 0
    var restoreCount = 0
    val deadResult =
      MehVpnService.executeSafeServerSwap(
        candidates = listOf(deadChallenger),
        previousActive = active,
        preVerifyIsolated = { null },
        launchAndVerifyLive = {
          liveLaunchCount++
          it to 100L
        },
        restorePrevious = { restoreCount++ },
        isLiveCoreRunning = { true },
      )
    assertNull(deadResult)
    assertEquals("Dead challenger must never stop or touch live Xray", 0, liveLaunchCount)
    assertEquals(0, restoreCount)

    // Case B: Flaky challenger passes isolated ping, fails live bind -> previousActive MUST be restored!
    var liveRunning = true
    var restoredConfig: V2RayConfig? = null
    val flakyResult =
      MehVpnService.executeSafeServerSwap(
        candidates = listOf(flakyChallenger),
        previousActive = active,
        preVerifyIsolated = { 120L },
        launchAndVerifyLive = {
          liveRunning = false
          null
        },
        restorePrevious = { prev ->
          restoredConfig = prev
          liveRunning = true
        },
        isLiveCoreRunning = { liveRunning },
      )
    assertNull(flakyResult)
    assertEquals("Previous active node must be restored immediately on live failure", active, restoredConfig)
    assertTrue("Live Xray core must NEVER be left stopped after a failed swap", liveRunning)

    // Case C: Good challenger passes both isolated ping and live verification -> succeeds cleanly!
    val goodResult =
      MehVpnService.executeSafeServerSwap(
        candidates = listOf(deadChallenger, goodChallenger),
        previousActive = active,
        preVerifyIsolated = { if (it.endpointKey == goodChallenger.endpointKey) 140L else null },
        launchAndVerifyLive = { it to 135L },
        restorePrevious = { throw AssertionError("Should not restore when swap succeeds") },
        isLiveCoreRunning = { true },
      )
    assertNotNull(goodResult)
    assertEquals(1, goodResult!!.first)
    assertEquals(goodChallenger.endpointKey, goodResult.second.endpointKey)
    assertEquals(135L, goodResult.third)
  }

  @Test
  fun nativeXrayPortBusyRetry_retriesAddressInUse_andFailsFastOnConfigError() {
    val sleeps = Collections.synchronizedList(mutableListOf<Long>())
    var attempts = 0
    val recovered =
      NativeXrayEngine.runWithPortBusyRetry(
        maxAttempts = 3,
        retryDelayMs = 250L,
        sleepFn = { sleeps.add(it) },
      ) { attempt ->
        attempts++
        if (attempt < 2) {
          NativeXrayEngine.StartResult(
            success = false,
            error = "listen tcp 127.0.0.1:20808: bind: address already in use",
          )
        } else {
          NativeXrayEngine.StartResult(success = true)
        }
      }
    assertTrue("Must recover when local SOCKS5 port finishes releasing", recovered.success)
    assertEquals(3, attempts)
    assertEquals(listOf(250L, 250L), sleeps)

    // Non-port error (e.g., invalid JSON config) must NOT waste retries.
    var configErrorAttempts = 0
    val fastFail =
      NativeXrayEngine.runWithPortBusyRetry(
        maxAttempts = 3,
        retryDelayMs = 250L,
        sleepFn = { throw AssertionError("Should not sleep on non-port config error") },
      ) {
        configErrorAttempts++
        NativeXrayEngine.StartResult(success = false, error = "infra/conf/serial: invalid json")
      }
    assertFalse(fastFail.success)
    assertEquals(1, configErrorAttempts)
  }

  @Test
  fun standbyPoolAndRefinementPolicy_prioritizesFastestStandby_andProtectsActiveSessions() {
    val active =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@a.example.org:443?security=tls&type=ws#Active"
      )!!
    val oldBackup =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@old.example.org:443?security=tls&type=ws#Old"
      )!!
    val fastStandby1 =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@fast1.example.org:443?security=tls&type=ws#Fast1"
      )!!
    val fastStandby2 =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@fast2.example.org:443?security=tls&type=ws#Fast2"
      )!!

    val reordered =
      MehVpnService.buildReorderedStandbyPool(
        active = active,
        standbyCandidates = listOf(fastStandby1, active, fastStandby2, fastStandby1),
        existingPool = listOf(active, oldBackup),
        maxSize = 8,
      )
    assertEquals(
      "Active node stays at index 0; fastest standby moves to index 1 for instant failover/switch",
      listOf(active.endpointKey, fastStandby1.endpointKey, fastStandby2.endpointKey, oldBackup.endpointKey),
      reordered.map { it.endpointKey },
    )

    // Normal healthy Iranian node (<= 1200ms) must NEVER be disrupted mid-session -> STORE_STANDBY_ONLY.
    assertEquals(
      MehVpnService.RefineAction.STORE_STANDBY_ONLY,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 650L,
        challengerPingMs = 210L,
        isUserTrafficActive = false,
      ),
    )

    // Marginal speedup on a very slow node (> 1200ms) must NOT disrupt -> STORE_STANDBY_ONLY.
    assertEquals(
      MehVpnService.RefineAction.STORE_STANDBY_ONLY,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 1500L,
        challengerPingMs = 1100L,
        isUserTrafficActive = false,
      ),
    )

    // Dramatic speedup on a sluggish node (> 1200ms) while user is idle -> UPGRADE_NOW.
    assertEquals(
      MehVpnService.RefineAction.UPGRADE_NOW,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 1600L,
        challengerPingMs = 240L,
        isUserTrafficActive = false,
      ),
    )

    // Same speedup during active user traffic -> DEFER_ACTIVE_TRAFFIC.
    assertEquals(
      MehVpnService.RefineAction.DEFER_ACTIVE_TRAFFIC,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 1600L,
        challengerPingMs = 240L,
        isUserTrafficActive = true,
      ),
    )
  }

  @Test
  fun failoverWithRollback_restoresPreviousNodeWhenBackupsFail_andSocialReportClassifiesTargets() {
    val active =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@active.example.org:443?security=tls&type=ws#Active"
      )!!
    val deadBackup =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@dead-b.example.org:443?security=tls&type=ws#DeadBackup"
      )!!
    val goodBackup =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@good-b.example.org:443?security=tls&type=ws#GoodBackup"
      )!!

    // Case 1: All standby backups fail -> MUST restore active and NOT mark active dead!
    val markedDead1 = mutableListOf<String>()
    var restored1: V2RayConfig? = null
    val fallbackResult =
      MehVpnService.executeFailoverWithRollback(
        failedCfg = active,
        standbyCandidates = listOf(deadBackup),
        launchAndVerify = { null },
        markDead = { markedDead1.add(it.endpointKey) },
        restoreFailed = { restored1 = it },
      )
    assertEquals(active.endpointKey, fallbackResult.first.endpointKey)
    assertNull(fallbackResult.second)
    assertEquals("Active node must be restored when all standby backups fail", active, restored1)
    assertFalse("Active node must not be permanently marked dead without a working replacement", active.endpointKey in markedDead1)
    assertTrue("Failed standby backup should be marked dead", deadBackup.endpointKey in markedDead1)

    // Case 2: Second standby backup passes -> switches cleanly and marks active + first dead backup.
    val markedDead2 = mutableListOf<String>()
    var restored2 = false
    val switchResult =
      MehVpnService.executeFailoverWithRollback(
        failedCfg = active,
        standbyCandidates = listOf(deadBackup, goodBackup),
        launchAndVerify = { cfg -> if (cfg.endpointKey == goodBackup.endpointKey) cfg to 180L else null },
        markDead = { markedDead2.add(it.endpointKey) },
        restoreFailed = { restored2 = true },
      )
    assertEquals(goodBackup.endpointKey, switchResult.first.endpointKey)
    assertEquals(180L, switchResult.second)
    assertFalse(restored2)
    assertTrue(active.endpointKey in markedDead2)
    assertTrue(deadBackup.endpointKey in markedDead2)

    // Verify SocialProbeReport distinguishes YouTube-only nodes from Instagram/Twitter-ready nodes.
    val ytOnly = MehVpnService.SocialProbeReport(youtubeMs = 310L, instagramMs = null, twitterMs = null)
    assertTrue(ytOnly.anyPassed)
    assertFalse("YouTube-only node must not be classified as socialPassed", ytOnly.socialPassed)
    assertEquals(310L, ytOnly.bestLatencyMs)

    val fullSocial = MehVpnService.SocialProbeReport(youtubeMs = 380L, instagramMs = 420L, twitterMs = 490L)
    assertTrue(fullSocial.anyPassed)
    assertTrue(fullSocial.socialPassed)
    assertTrue(fullSocial.formatDiagnosticLog().contains("اینستاگرام ✓ 420ms"))
    assertTrue(fullSocial.formatDiagnosticLog().contains("توییتر ✓ 490ms"))
  }

  @Test
  fun manifestAndNativeBindings_declareVpnServiceAndExposeRequiredTunnelEntryPoints() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val vpnIntent = Intent(VpnService.SERVICE_INTERFACE).setPackage(context.packageName)
    val resolved = context.packageManager.queryIntentServices(vpnIntent, 0)
    assertTrue(
      "MehVpnService must be registered with android.net.VpnService action in AndroidManifest",
      resolved.any {
        it.serviceInfo.name == MehVpnService::class.java.name &&
          it.serviceInfo.permission == android.Manifest.permission.BIND_VPN_SERVICE
      },
    )

    // Verify native tunnel & Xray bridge classes/methods remain intact on classpath without
    // triggering Android .so static initializers on the JVM host.
    val loader = this::class.java.classLoader
    val tproxyCls = Class.forName("org.amnezia.awg.hevtunnel.TProxyService", false, loader)
    assertNotNull(tproxyCls.getDeclaredMethod("TProxyStartService", String::class.java, Int::class.javaPrimitiveType))
    assertNotNull(tproxyCls.getDeclaredMethod("TProxyStopService"))

    val libXrayCls = Class.forName("libXray.LibXray", false, loader)
    assertNotNull(libXrayCls.getDeclaredMethod("runXrayFromJSON", String::class.java))
    assertNotNull(libXrayCls.getDeclaredMethod("stopXray"))
    assertNotNull(libXrayCls.getDeclaredMethod("getXrayState"))
    assertNotNull(libXrayCls.getDeclaredMethod("ping", String::class.java))
  }

  @Test
  fun verifiedServerPoolStore_ranksFastestPrunesExpiredAndDeadAndRotatesBatches() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    VerifiedServerPoolStore.clear(context)

    val now = 1_800_000_000_000L
    val slow =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@slow.example.org:443?security=tls&type=ws#Slow"
      )!!.copy(latencyMs = 420L, speedScore = 50.0)
    val fast =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@fast.example.org:443?security=tls&type=ws#Fast"
      )!!.copy(latencyMs = 115L, speedScore = 180.0)
    val medium =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@med.example.org:443?security=tls&type=ws#Med"
      )!!.copy(latencyMs = 210L, speedScore = 120.0)

    // Older entry tested 2 hours ago (valid within 6h TTL, but not within 45m fresh window).
    VerifiedServerPoolStore.upsertVerified(context, listOf(slow), nowMs = now - 2L * 60L * 60L * 1000L)
    // Fresh entries tested right now.
    VerifiedServerPoolStore.upsertVerified(context, listOf(medium, fast), nowMs = now)

    val allCached = VerifiedServerPoolStore.getFastest(context, nowMs = now)
    assertEquals(
      "Servers must be sorted fastest-first by latencyMs",
      listOf(fast.endpointKey, medium.endpointKey, slow.endpointKey),
      allCached.map { it.endpointKey },
    )

    val freshOnly = VerifiedServerPoolStore.getFastestFresh(context, nowMs = now)
    assertEquals(
      "Fresh query must exclude servers older than 45 minutes",
      listOf(fast.endpointKey, medium.endpointKey),
      freshOnly.map { it.endpointKey },
    )

    // Marking a server dead immediately hides it from VerifiedServerPoolStore reads.
    DeadServerStore.markDead(context, fast.endpointKey)
    val afterDead = VerifiedServerPoolStore.getFastestFresh(context, nowMs = now)
    assertEquals(listOf(medium.endpointKey), afterDead.map { it.endpointKey })

    // Hard TTL expiry (after 7 hours) prunes stale servers completely.
    val afterExpiry = VerifiedServerPoolStore.getFastest(context, nowMs = now + 7L * 60L * 60L * 1000L)
    assertTrue("Servers past 6h TTL must expire", afterExpiry.isEmpty())

    // Batch rotation cursor wraps cleanly across runs.
    assertEquals(0, VerifiedServerPoolStore.nextScanBatchIndex(context, totalBatches = 3))
    assertEquals(1, VerifiedServerPoolStore.nextScanBatchIndex(context, totalBatches = 3))
    assertEquals(2, VerifiedServerPoolStore.nextScanBatchIndex(context, totalBatches = 3))
    assertEquals(0, VerifiedServerPoolStore.nextScanBatchIndex(context, totalBatches = 3))
  }

  @Test
  fun gentleScanPolicy_protectsBatteryPowerSaverForegroundConnectAndMeteredData() {
    val now = 1_800_000_000_000L

    // Power Save Mode -> always skip.
    assertEquals(
      GentleScanDecision.SKIP_POWER_SAVE_MODE,
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = true,
        batteryPercent = 85,
        isCharging = false,
        isForegroundConnectBusy = false,
        lastScanAtMs = 0L,
        nowMs = now,
        cachedFreshCount = 0,
      ),
    )

    // Low battery while discharging -> skip; while charging -> allow.
    assertEquals(
      GentleScanDecision.SKIP_LOW_BATTERY,
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = false,
        batteryPercent = 12,
        isCharging = false,
        isForegroundConnectBusy = false,
        lastScanAtMs = 0L,
        nowMs = now,
        cachedFreshCount = 0,
      ),
    )
    assertEquals(
      GentleScanDecision.RUN,
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = false,
        batteryPercent = 12,
        isCharging = true,
        isForegroundConnectBusy = false,
        lastScanAtMs = 0L,
        nowMs = now,
        cachedFreshCount = 0,
      ),
    )

    // Foreground manual connect in flight -> skip so background never competes.
    assertEquals(
      GentleScanDecision.SKIP_FOREGROUND_BUSY,
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = false,
        batteryPercent = 90,
        isCharging = false,
        isForegroundConnectBusy = true,
        lastScanAtMs = 0L,
        nowMs = now,
        cachedFreshCount = 0,
      ),
    )

    // Normal cooldown (10 min) enforced when pool is already healthy.
    assertEquals(
      GentleScanDecision.SKIP_COOLDOWN,
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = false,
        batteryPercent = 90,
        isCharging = false,
        isForegroundConnectBusy = false,
        lastScanAtMs = now - 5L * 60L * 1000L,
        nowMs = now,
        cachedFreshCount = 6,
      ),
    )

    // Metered cellular limits must be strictly lighter than Wi-Fi limits.
    val wifiLimits = GentleScanPolicy.computeLimits(isMetered = false)
    val cellularLimits = GentleScanPolicy.computeLimits(isMetered = true)
    assertTrue(cellularLimits.stage1Concurrency < wifiLimits.stage1Concurrency)
    assertTrue(cellularLimits.maxConfigsToProbe < wifiLimits.maxConfigsToProbe)
    assertTrue(cellularLimits.sourcesPerBatch <= wifiLimits.sourcesPerBatch)
    assertTrue(wifiLimits.stage1Concurrency <= 4)
  }

  @Test
  fun backgroundScannerJobService_isManifestDeclaredAndSchedulesIdempotently() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    VerifiedServerPoolStore.clear(context)

    val svcInfo =
      context.packageManager.getServiceInfo(
        ComponentName(context, BackgroundServerScannerJobService::class.java),
        0,
      )
    assertEquals(android.app.job.JobService.PERMISSION_BIND, svcInfo.permission)
    assertFalse("Background JobService must not be exported", svcInfo.exported)

    assertTrue(BackgroundServerScanScheduler.ensurePeriodicScheduled(context))
    val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
    val periodicJob = scheduler.getPendingJob(BackgroundServerScanScheduler.PERIODIC_JOB_ID)
    assertNotNull("Periodic gentle background job must be scheduled", periodicJob)
    assertEquals(JobInfo.NETWORK_TYPE_ANY, periodicJob!!.networkType)
    assertTrue(periodicJob.intervalMillis >= BackgroundServerScanScheduler.PERIODIC_INTERVAL_MS)

    // Warm-up job schedules when fresh cache is empty.
    assertTrue(BackgroundServerScanScheduler.scheduleWarmupIfNeeded(context))
    assertNotNull(scheduler.getPendingJob(BackgroundServerScanScheduler.WARMUP_JOB_ID))

    // Once pool has >= 4 fresh servers, warm-up is skipped to avoid unnecessary work.
    val now = System.currentTimeMillis()
    val fourFresh =
      (1..4).map { idx ->
        V2RayConfigParser.parseSingleUri(
          "vless://11111111-2222-3333-4444-555555555555@fresh$idx.example.org:443?security=tls&type=ws#Fresh$idx"
        )!!.copy(latencyMs = 100L + idx * 10L)
      }
    VerifiedServerPoolStore.upsertVerified(context, fourFresh, nowMs = now)
    assertFalse(BackgroundServerScanScheduler.scheduleWarmupIfNeeded(context))
  }

  @Test
  fun privateDnsDetector_flagsStrictCustomAndIranianDns_andIgnoresOffOrAutomatic() {
    // Default Android modes ("off", "opportunistic"/Automatic, or unset) must NEVER trigger false alarms.
    val offStatus =
      PrivateDnsDetector.evaluate(
        globalMode = "off",
        globalSpecifier = "free.shecan.ir",
        linkPrivateDnsActive = false,
        linkPrivateDnsServerName = null,
      )
    assertFalse("mode=off must not warn even if an old specifier string remains", offStatus.isStrictCustomActive)

    val autoStatus =
      PrivateDnsDetector.evaluate(
        globalMode = "opportunistic",
        globalSpecifier = "dns.403.online",
        linkPrivateDnsActive = true,
        linkPrivateDnsServerName = null,
      )
    assertFalse("mode=opportunistic (Automatic) must not warn", autoStatus.isStrictCustomActive)

    val unsetStatus =
      PrivateDnsDetector.evaluate(
        globalMode = null,
        globalSpecifier = null,
        linkPrivateDnsActive = false,
        linkPrivateDnsServerName = null,
      )
    assertFalse("Unset Private DNS must not warn", unsetStatus.isStrictCustomActive)

    // Strict Iranian anti-sanction DNS hostnames MUST be flagged with isLikelyIranianSanctionDns = true.
    for (iranianHost in listOf("free.shecan.ir", "dns.403.online", "dns.electro.team", "radar.game", "custom.example.ir")) {
      val status =
        PrivateDnsDetector.evaluate(
          globalMode = "hostname",
          globalSpecifier = iranianHost,
          linkPrivateDnsActive = true,
          linkPrivateDnsServerName = iranianHost,
        )
      assertTrue("$iranianHost must be flagged as strict custom Private DNS", status.isStrictCustomActive)
      assertTrue("$iranianHost must be classified as likely Iranian anti-sanction DNS", status.isLikelyIranianSanctionDns)
      assertEquals(iranianHost, status.hostname)
    }

    // Strict generic DoT hostname MUST warn (bypasses TUN mapdns), but NOT be mislabeled as Iranian DNS.
    val googleDoT =
      PrivateDnsDetector.evaluate(
        globalMode = "hostname",
        globalSpecifier = "dns.google",
        linkPrivateDnsActive = true,
        linkPrivateDnsServerName = "dns.google",
      )
    assertTrue("Strict dns.google must be flagged", googleDoT.isStrictCustomActive)
    assertFalse("dns.google must not be labeled Iranian sanction DNS", googleDoT.isLikelyIranianSanctionDns)
    assertEquals("dns.google", googleDoT.hostname)

    // Even when Settings.Global is restricted/null on some OEM ROMs, LinkProperties hostname must still trigger detection.
    val linkOnlyStatus =
      PrivateDnsDetector.evaluate(
        globalMode = null,
        globalSpecifier = null,
        linkPrivateDnsActive = true,
        linkPrivateDnsServerName = "pro.shecan.ir",
      )
    assertTrue("LinkProperties strict Private DNS must trigger even when Settings.Global is null", linkOnlyStatus.isStrictCustomActive)
    assertTrue(linkOnlyStatus.isLikelyIranianSanctionDns)
    assertEquals("pro.shecan.ir", linkOnlyStatus.hostname)
  }

  @Test
  fun upgradeCacheReset_clearsStalePoolAndDeadStoreOncePerAppVersion() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    VerifiedServerPoolStore.clear(context)
    DeadServerStore.clear(context)

    val oldServer =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@old-cache.example.org:443?security=tls&type=ws#OldCache"
      )!!.copy(latencyMs = 150L)
    val deadServer =
      V2RayConfigParser.parseSingleUri(
        "vless://11111111-2222-3333-4444-555555555555@dead-cache.example.org:443?security=tls&type=ws#DeadCache"
      )!!

    val t1 = 1_700_000_000_000L
    val t2 = 1_700_000_050_000L

    // Simulate pre-upgrade state left over from an older APK version.
    VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 100, installUpdateTimeMs = t1)
    VerifiedServerPoolStore.upsertVerified(context, listOf(oldServer))
    DeadServerStore.markDead(context, deadServer.endpointKey)
    context.getSharedPreferences("meh_last_server_prefs", Context.MODE_PRIVATE)
      .edit()
      .putString("saved_candidates_json", """[{"rawUri":"${oldServer.rawUri}"}]""")
      .apply()

    // Same version + same install timestamp restart MUST preserve the fresh cache.
    assertFalse(
      VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 100, installUpdateTimeMs = t1)
    )
    assertEquals(1, VerifiedServerPoolStore.getFastest(context).size)
    assertTrue(DeadServerStore.isDead(context, deadServer.endpointKey))

    // Upgrading to a new versionCode MUST wipe all stale caches once so it behaves like a clean install.
    assertTrue(
      VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 101, installUpdateTimeMs = t1)
    )
    assertTrue("Stale verified pool must be cleared on upgrade", VerifiedServerPoolStore.getFastest(context).isEmpty())
    assertFalse("Stale dead-server blacklist must be cleared on upgrade", DeadServerStore.isDead(context, deadServer.endpointKey))
    assertNull(
      "Stale last-connected candidates must be cleared on upgrade",
      context.getSharedPreferences("meh_last_server_prefs", Context.MODE_PRIVATE)
        .getString("saved_candidates_json", null),
    )

    // Subsequent launches on version 101 with the same install timestamp must NOT clear newly discovered servers.
    VerifiedServerPoolStore.upsertVerified(context, listOf(oldServer))
    assertFalse(
      VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 101, installUpdateTimeMs = t1)
    )
    assertEquals(1, VerifiedServerPoolStore.getFastest(context).size)

    // In-place reinstall of a new APK build even with the SAME versionCode (newer lastUpdateTime)
    // MUST wipe stale caches once, then stay stable on subsequent launches.
    assertTrue(
      VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 101, installUpdateTimeMs = t2)
    )
    assertTrue("In-place APK reinstall must clear stale pool", VerifiedServerPoolStore.getFastest(context).isEmpty())
    VerifiedServerPoolStore.upsertVerified(context, listOf(oldServer))
    assertFalse(
      VerifiedServerPoolStore.resetCachesIfAppUpdated(context, currentVersionCode = 101, installUpdateTimeMs = t2)
    )
    assertEquals(1, VerifiedServerPoolStore.getFastest(context).size)
  }
}

