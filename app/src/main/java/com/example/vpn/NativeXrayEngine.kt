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
    return when (config.protocol) {
      V2RayProtocol.TUIC -> false
      else -> true
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
   * Starts native Xray-core directly attached to the detached Android VpnService TUN [tunFd].
   */
  fun startTunnel(
    datDir: String,
    tunFd: Int,
    configJson: String,
    protectFd: (Int) -> Boolean,
  ): StartResult {
    synchronized(engineLock) {
      return try {
        activeProtectCallback = protectFd
        try {
          if (LibXray.getXrayState()) {
            LibXray.stopXray()
          }
        } catch (_: Throwable) {}

        LibXray.registerDialerController(dialerController)
        LibXray.registerListenerController(dialerController)
        LibXray.setTunFd(tunFd)

        val reqB64 = LibXray.newXrayRunFromJSONRequest(datDir, configJson)
        val rawRespB64 = LibXray.runXrayFromJSON(reqB64)
        val parsed = parseResponseJson(rawRespB64)
        val ok = parsed?.optBoolean("success", false) ?: false
        if (ok) {
          StartResult(success = true)
        } else {
          val errMsg = parsed?.optString("error").orEmpty().ifBlank { "runXrayFromJSON failed" }
          Log.w(TAG, "Native Xray start error: $errMsg")
          StartResult(success = false, error = errMsg)
        }
      } catch (t: Throwable) {
        Log.e(TAG, "Native Xray exception", t)
        StartResult(
          success = false,
          error = t.localizedMessage ?: t.javaClass.simpleName,
        )
      }
    }
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
