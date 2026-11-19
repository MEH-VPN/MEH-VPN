package com.example.vpn

import android.util.Base64
import android.util.Log
import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.File
import java.net.ServerSocket
import libXray.DialerController
import libXray.LibXray
import org.json.JSONObject

/**
 * Native Go Xray-core bridge backed by `libXray.LibXray` (Xray-core v26.x).
 *
 * Replaces the Kotlin packet-by-socket relay (`LocalV2RayProxyServer`) and `tun2socks` bridge on
 * the live VPN data path with native Go `Xray-core` + built-in `proxy/tun` (`setTunFd`) and
 * `DialerController.protectFd` so all TCP, UDP, DNS, TLS, uTLS, Fragment, Reality, Vision, WS,
 * gRPC, HTTPUpgrade, XHTTP, VMess, VLESS, Trojan, Shadowsocks, Hysteria2, and WireGuard flows
 * run natively at C/Go throughput.
 */
object NativeXrayEngine {

  private const val TAG = "NativeXrayEngine"
  private val engineLock = Any()

  @Volatile private var activeProtectCallback: ((Int) -> Boolean)? = null

  private val dialerController =
    object : DialerController {
      override fun protectFd(fd: Long): Boolean {
        val cb = activeProtectCallback ?: return true
        return try {
          cb(fd.toInt())
        } catch (_: Throwable) {
          false
        }
      }
    }

  data class StartResult(
    val success: Boolean,
    val error: String? = null,
  )

  fun xrayVersion(): String {
    return try {
      decodeResponseDataString(LibXray.xrayVersion()) ?: "Xray-core"
    } catch (_: Throwable) {
      "Xray-core"
    }
  }

  fun isRunning(): Boolean {
    return try {
      LibXray.getXrayState()
    } catch (_: Throwable) {
      false
    }
  }

  /**
   * Returns true if [config] can be executed natively by Xray-core (`libXray`).
   * Custom GFW-knocker magic version variants (`MVLESS` `0x96`, `JVLESS` `0x78`) and `TUIC`
   * are automatically handled cleanly or converted when compatible.
   */
  fun supportsNativeXray(config: V2RayConfig): Boolean {
    if (config.protocol == V2RayProtocol.TUIC) return false
    if (config.protocol == V2RayProtocol.SERVERLESS) return true
    if (config.address.isBlank() || config.port !in 1..65535) return false
    val net = config.network.lowercase().trim()
    // Legacy http/h2 transport was removed in Xray-core v26 (`unknown transport protocol: http`).
    if (net == "h2" || net == "http") return false
    if (config.security.equals("reality", ignoreCase = true)) {
      val normalizedNet =
        when (net) {
          "grpc", "gun" -> "grpc"
          "xhttp", "splithttp" -> "xhttp"
          "tcp", "" -> "tcp"
          else -> net
        }
      if (normalizedNet !in setOf("tcp", "xhttp", "grpc")) return false
      if (config.pbk.isBlank()) return false
    }
    return when (config.protocol) {
      V2RayProtocol.SOCKS5,
      V2RayProtocol.HTTP_PROXY -> true
      V2RayProtocol.WIREGUARD -> config.authId.isNotBlank() && config.publicKey.isNotBlank()
      else -> config.authId.isNotBlank()
    }
  }

  fun allocateLocalPort(): Int {
    return try {
      ServerSocket(0).use { it.localPort }
    } catch (_: Throwable) {
      10808
    }
  }

  /**
   * Starts native Xray-core. When [tunFd] is non-null, attaches directly to the TUN fd; when null,
   * runs in SOCKS5 inbound mode (paired with `hev-socks5-tunnel` owning the Android TUN fd).
   */
  fun startTunnel(
    datDir: String,
    tunFd: Int? = null,
    configJson: String,
    protectFd: (Int) -> Boolean,
  ): StartResult {
    synchronized(engineLock) {
      return try {
        activeProtectCallback = protectFd
        try {
          if (LibXray.getXrayState()) {
            LibXray.stopXray()
            var waitedMs = 0L
            while (waitedMs < 600L && LibXray.getXrayState()) {
              try {
                Thread.sleep(40L)
              } catch (_: InterruptedException) {
                break
              }
              waitedMs += 40L
            }
            try {
              Thread.sleep(120L)
            } catch (_: InterruptedException) {}
          }
        } catch (_: Throwable) {}

        LibXray.registerDialerController(dialerController)
        if (tunFd != null && tunFd >= 0) {
          LibXray.setTunFd(tunFd)
        }

        val reqB64 = LibXray.newXrayRunFromJSONRequest(datDir, configJson)
        val result =
          runWithPortBusyRetry(maxAttempts = 3, retryDelayMs = 250L) {
            val rawRespB64 = LibXray.runXrayFromJSON(reqB64)
            val parsed = parseResponseJson(rawRespB64)
            val ok = parsed?.optBoolean("success", false) ?: false
            if (ok) {
              StartResult(success = true)
            } else {
              val errMsg = parsed?.optString("error").orEmpty().ifBlank { "runXrayFromJSON failed" }
              StartResult(success = false, error = errMsg)
            }
          }
        if (!result.success) {
          Log.w(TAG, "Native Xray start error: ${result.error}")
        }
        result
      } catch (t: Throwable) {
        Log.e(TAG, "Native Xray exception", t)
        StartResult(
          success = false,
          error = t.localizedMessage ?: t.javaClass.simpleName,
        )
      }
    }
  }

  internal fun runWithPortBusyRetry(
    maxAttempts: Int = 3,
    retryDelayMs: Long = 250L,
    sleepFn: (Long) -> Unit = { ms ->
      try {
        Thread.sleep(ms)
      } catch (_: InterruptedException) {}
    },
    attemptStart: (Int) -> StartResult,
  ): StartResult {
    var lastResult = StartResult(success = false, error = "runXrayFromJSON failed")
    for (attempt in 0 until maxAttempts.coerceAtLeast(1)) {
      val res = attemptStart(attempt)
      if (res.success) return res
      lastResult = res
      val err = res.error.orEmpty()
      val isPortBusy =
        err.contains("address already in use", ignoreCase = true) ||
          err.contains("bind:", ignoreCase = true)
      if (!isPortBusy || attempt == maxAttempts - 1) {
        break
      }
      if (retryDelayMs > 0L) {
        sleepFn(retryDelayMs)
      }
    }
    return lastResult
  }

  fun stopTunnel() {
    synchronized(engineLock) {
      try {
        if (LibXray.getXrayState()) {
          LibXray.stopXray()
        }
      } catch (_: Throwable) {
      } finally {
        activeProtectCallback = null
      }
    }
  }

  /**
   * Measures outbound latency using native Xray-core (`LibXray.ping`).
   * Returns latency in ms, or null if unsupported/timed out.
   */
  fun pingConfig(
    datDir: String,
    tempDir: File,
    config: V2RayConfig,
    url: String = "https://connectivitycheck.gstatic.com/generate_204",
    timeoutSec: Int = 5,
    protectFd: ((Int) -> Boolean)? = null,
  ): Long? {
    var tempFile: File? = null
    return try {
      if (protectFd != null) {
        activeProtectCallback = protectFd
        LibXray.registerDialerController(dialerController)
      }
      val freePort = allocateLocalPort()
      val configJson =
        GfwKnockerXrayCore.buildXrayCoreJson(
          config = config,
          includeTunInbound = false,
          localSocksPort = freePort,
        )
      tempDir.mkdirs()
      tempFile = File.createTempFile("xray_ping_", ".json", tempDir)
      tempFile.writeText(configJson)

      val reqJson =
        JSONObject().apply {
          put("datDir", datDir)
          put("configPath", tempFile.absolutePath)
          put("timeout", timeoutSec.coerceIn(1, 15))
          put("url", url)
          put("proxy", "socks5://127.0.0.1:$freePort")
        }
      val reqB64 = encodeBase64(reqJson.toString().toByteArray(Charsets.UTF_8))
      val respB64 = LibXray.ping(reqB64)
      val respObj = parseResponseJson(respB64) ?: return null
      if (!respObj.optBoolean("success", false)) return null
      val delay = respObj.optLong("data", -1L)
      if (delay in 1L..9999L) delay else null
    } catch (_: Throwable) {
      null
    } finally {
      try {
        tempFile?.delete()
      } catch (_: Throwable) {}
    }
  }

  private fun parseResponseJson(rawOrBase64: String?): JSONObject? {
    if (rawOrBase64.isNullOrBlank()) return null
    val trimmed = rawOrBase64.trim()
    val decoded =
      if (trimmed.startsWith("{")) {
        trimmed
      } else {
        decodeBase64ToString(trimmed) ?: trimmed
      }
    return try {
      JSONObject(decoded)
    } catch (_: Throwable) {
      null
    }
  }

  private fun decodeResponseDataString(rawOrBase64: String?): String? {
    val obj = parseResponseJson(rawOrBase64) ?: return null
    return if (obj.optBoolean("success", false)) {
      obj.optString("data").ifBlank { null }
    } else {
      null
    }
  }

  private fun encodeBase64(bytes: ByteArray): String {
    return try {
      Base64.encodeToString(bytes, Base64.NO_WRAP)
    } catch (_: Throwable) {
      java.util.Base64.getEncoder().encodeToString(bytes)
    }
  }

  private fun decodeBase64ToString(encoded: String): String? {
    return try {
      String(Base64.decode(encoded, Base64.DEFAULT), Charsets.UTF_8)
    } catch (_: Throwable) {
      try {
        String(java.util.Base64.getDecoder().decode(encoded), Charsets.UTF_8)
      } catch (_: Throwable) {
        null
      }
    }
  }
}
