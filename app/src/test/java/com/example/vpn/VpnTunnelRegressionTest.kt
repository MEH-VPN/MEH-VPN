package com.example.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.test.core.app.ApplicationProvider
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
      "Expected verifier to probe both primary and fallback HTTPS endpoints, saw $requestedTargets",
      requestedTargets.size >= 2,
    )
    assertTrue(
      "Verifier must probe www.google.com:443, saw $requestedTargets",
      requestedTargets.any { it.first == "www.google.com" && it.second == 443 },
    )
    assertTrue(
      "Verifier must fall back to cp.cloudflare.com:443, saw $requestedTargets",
      requestedTargets.any { it.first == "cp.cloudflare.com" && it.second == 443 },
    )
    assertTrue(
      "Verifier must NEVER fall back to plain HTTP port 80, saw $requestedTargets",
      requestedTargets.none { it.second == 80 },
    )
  }

  @Test
  fun hevTunnelYamlAndVpnTopology_matchMapDnsAndXraySocksContract() {
    val socksPort = 24808
    val yaml =
      GfwKnockerXrayCore.buildHevSocks5TunnelYaml(
        socksPort = socksPort,
        tunMtu = MehVpnService.TUN_MTU,
        tunIpv4 = MehVpnService.TUN_IPV4_ADDRESS,
        mapDnsAddress = MehVpnService.MAP_DNS_ADDRESS,
      )

    // TUN IPv4 and mapdns IPv4 must be distinct hosts inside the /30 subnet so Android routes DNS into TUN.
    assertEquals("10.10.14.1", MehVpnService.TUN_IPV4_ADDRESS)
    assertEquals("10.10.14.2", MehVpnService.MAP_DNS_ADDRESS)
    assertTrue(yaml.contains("mtu: ${MehVpnService.TUN_MTU}"))
    assertTrue(yaml.contains("ipv4: ${MehVpnService.TUN_IPV4_ADDRESS}"))
    assertTrue(yaml.contains("port: $socksPort"))
    assertTrue(yaml.contains("address: 127.0.0.1"))
    assertTrue("hev-socks5-tunnel must use standard RFC1928 UDP mode for Xray", yaml.contains("udp: 'udp'"))
    assertFalse("udp: 'tcp' is unsupported by Xray socks inbound", yaml.contains("udp: 'tcp'"))
    assertTrue(yaml.contains("address: ${MehVpnService.MAP_DNS_ADDRESS}"))
    assertTrue(yaml.contains("network: 100.64.0.0"))
    assertTrue(yaml.contains("netmask: 255.192.0.0"))
    assertFalse("Avoid reserved Class E 240.0.0.0/4 on Android kernels", yaml.contains("240.0.0.0"))
    assertTrue("Must use valid hev-socks5-tunnel key read-write-timeout", yaml.contains("read-write-timeout:"))
    assertFalse("tcp-read-write-timeout is rejected by libhev-socks5-tunnel.so", yaml.contains("tcp-read-write-timeout:"))
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
        val inbounds = root.getJSONArray("inbounds")
        assertEquals("${cfg.remarks} live mode must only bind socks-in (hev-tunnel owns TUN)", 1, inbounds.length())
        val socksIn = inbounds.getJSONObject(0)
        assertEquals("socks-in", socksIn.getString("tag"))
        assertEquals("127.0.0.1", socksIn.getString("listen"))
        assertEquals(20808, socksIn.getInt("port"))
        assertTrue(socksIn.getJSONObject("settings").getBoolean("udp"))

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
          if (r.optString("outboundTag") == "direct" && r.has("ip")) {
            val ipText = r.getJSONArray("ip").toString()
            if (ipText.contains("100.64.0.0")) {
              directBypassesMapDnsPool = true
            }
          }
        }
        assertTrue("${cfg.remarks} must block QUIC UDP:443 for Instagram/Chrome/YouTube", hasQuicUdp443Block)
        assertTrue("${cfg.remarks} must redirect port 53 to dns-out", hasDnsPort53Rule)
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

    // Marginal speedup (<40% and >250ms) must NOT disrupt the user -> STORE_STANDBY_ONLY.
    assertEquals(
      MehVpnService.RefineAction.STORE_STANDBY_ONLY,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 500L,
        challengerPingMs = 390L,
        isUserTrafficActive = false,
      ),
    )

    // Significant speedup while user is idle within 2-min window -> UPGRADE_NOW.
    assertEquals(
      MehVpnService.RefineAction.UPGRADE_NOW,
      MehVpnService.decideBackgroundRefineAction(
        forceFailover = false,
        initialUpgradeCompleted = false,
        elapsedSinceConnectMs = 20_000L,
        currentPingMs = 650L,
        challengerPingMs = 210L,
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
        currentPingMs = 650L,
        challengerPingMs = 210L,
        isUserTrafficActive = true,
      ),
    )
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
}
