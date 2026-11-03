package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException

/**
 * Unified Circumvention & Fragmentation Core combining:
 * - https://github.com/GFW-knocker/Xray-core (v26.10.3-mahsa-r2)
 * - https://github.com/CluvexStudio/Aether (`sni_host_range` midpoint SNI split + Anycast pool + H2 fragment)
 * - https://github.com/WhiteDNS (WhiteDNS Clean-IP + ByeDPI SNI split)
 * - https://github.com/patterniha (Serverless Frag-A/B, Free-Configs F&F, Z-E-U-S, SNI-Spoofing, MMDF)
 *
 * CRITICAL ANDROID 9 (API 28) COMPATIBILITY:
 * Android 9 Conscrypt's `SSLSocketFactory.createSocket(Socket, ...)` inspects the raw OS `FileDescriptor`
 * on `java.net.Socket` subclasses via reflection (`ConscryptFileDescriptorSocket`), throwing
 * `SocketException: Socket is not connected` if given a wrapper `Socket` whose superclass `fd` is `-1`.
 * To guarantee 100% compatibility on Android 5 through 16 (including Samsung Galaxy S8 on Android 9):
 * - We use [openSslEngineOverStreams] (`javax.net.ssl.SSLEngine`) whenever TLS runs over a
 *   [FragmentWriterOutputStream] or over an existing V2Ray tunnel stream!
 * - We split the TLS ClientHello at the TCP segment level (preserving 100% RFC 8446 TLS 1.2/1.3
 *   wire validity so strict Cloudflare/Xray/BoringSSL servers never reject the handshake).
 */
object GfwKnockerXrayCore {

  const val CORE_VERSION =
    "Mahsa-XrayCore v26.10.3 + CluvexStudio/Aether + WhiteDNS + Patterniha Engine"

  const val GFW_KNOCKER_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

  const val VLESS_VERSION_STANDARD: Byte = 0x00
  const val VLESS_VERSION_MVLESS: Byte = 150.toByte() // 0x96 in GFW-knocker/Xray-core/proxy/mvless
  const val VLESS_VERSION_JVLESS: Byte = 0x78.toByte() // 'x' in GFW-knocker/Xray-core/proxy/jvless

  /**
   * Patterniha custom cipher suite preference list from `patterniha/Free-Configs` & `patterniha/PattNG`.
   */
  val PATTERNIHA_CIPHER_SUITES =
    listOf(
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    )

  /**
   * CluvexStudio/Aether Anycast Gateway Pool (`aether/src/consts.rs` -> `CDN_ANYCAST_POOL`).
   */
  val AETHER_CDN_ANYCAST_GATEWAYS =
    listOf(
      "188.114.98.0",
      "188.114.97.0",
      "188.114.96.0",
      "188.114.99.0",
      "172.64.0.1",
      "172.65.0.1",
      "172.66.0.1",
      "172.67.0.1",
      "104.16.0.1",
      "104.17.0.1",
      "104.18.0.1",
      "104.19.0.1",
      "104.20.0.1",
      "104.21.0.1",
      "104.24.0.1",
    )

  private val rng = SecureRandom()

  data class FragmentConfig(
    val profileId: String = "gfw_knocker",
    val packetsFrom: Int = 0,
    val packetsTo: Int = 1,
    val lengthMin: Int = 10,
    val lengthMax: Int = 30,
    val intervalMinMs: Long = 2L,
    val intervalMaxMs: Long = 6L,
    val batchMin: Int = 1,
    val batchMax: Int = 2,
    val emptyRecordMinor: Int = 0,
    val sniMidpointSplit: Boolean = false,
    val cyclicRecordLengths: IntArray? = null,
    val tcpSplitLengths: IntArray? = null,
    val tcpMaxSplit: Int = 0,
    val emitTlsRecordHeaders: Boolean = false,
  ) {
    companion object {
      /**
       * Default `tlshello` configuration for GFW-knocker/Xray-core:
       * Splits the TLS ClientHello across 14–32 byte TCP segments with 2–5ms pacing.
       */
      val DEFAULT_TLS_HELLO =
        FragmentConfig(
          profileId = "gfw_knocker",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 14,
          lengthMax = 32,
          intervalMinMs = 2L,
          intervalMaxMs = 5L,
          sniMidpointSplit = true,
        )

      /**
       * CluvexStudio/Aether (`https://github.com/CluvexStudio/Aether/blob/main/aether/src/fragment.rs`):
       * Parses the TLS ClientHello (`sni_host_range`), splits the first write at the exact midpoint
       * of the SNI hostname (`start + (end - start) / 2`), and sends remaining bytes in `8-16` byte chunks
       * with `2-6ms` delay.
       */
      val AETHER_SNI_SPLIT =
        FragmentConfig(
          profileId = "aether_sni_split",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 8,
          lengthMax = 16,
          intervalMinMs = 2L,
          intervalMaxMs = 6L,
          sniMidpointSplit = true,
        )

      /**
       * WhiteDNS (`https://github.com/WhiteDNS`):
       * Splits the TLS ClientHello at the SNI midpoint followed by 24–48 byte segments.
       */
      val WHITEDNS_BYEDPI =
        FragmentConfig(
          profileId = "whitedns_byedpi",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 24,
          lengthMax = 48,
          intervalMinMs = 1L,
          intervalMaxMs = 3L,
          sniMidpointSplit = true,
        )

      /**
       * Patterniha `Serverless-v52-fragA` (`patterniha/Serverless-for-Iran/Serverless-fragA.jsonc`):
       * TCP segments of `[6, 98, 1]` (landing right inside the SNI extension at byte 104) + `[114, 1]`.
       */
      val PATTERNIHA_FRAG_A =
        FragmentConfig(
          profileId = "patterniha_frag_a",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 6,
          lengthMax = 98,
          intervalMinMs = 1L,
          intervalMaxMs = 1L,
          cyclicRecordLengths = intArrayOf(6, 98, 1),
          tcpSplitLengths = intArrayOf(6, 98, 1, 114, 1),
          tcpMaxSplit = 14,
        )

      /**
       * Patterniha `Serverless-v52-fragB` & `Free-Configs F&F` (`patterniha/Serverless-for-Iran/Serverless-fragB.jsonc`):
       * TCP segments of `[104, 1]` (landing right inside the SNI extension at byte 104) + `[114, 1]`.
       */
      val PATTERNIHA_FRAG_B =
        FragmentConfig(
          profileId = "patterniha_frag_b",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 1,
          lengthMax = 104,
          intervalMinMs = 1L,
          intervalMaxMs = 1L,
          cyclicRecordLengths = intArrayOf(0, 104, 1),
          tcpSplitLengths = intArrayOf(104, 1, 114, 1),
          tcpMaxSplit = 14,
        )

      /**
       * Patterniha `SNI-Spoofing` & `MMDF` (`patterniha/SNI-Spoofing` + `patterniha/MMDF`):
       * Micro-splits the TLS ClientHello across `2, 1, 3, 1` byte TCP segments around the SNI.
       */
      val PATTERNIHA_SNI_SPOOF =
        FragmentConfig(
          profileId = "patterniha_sni_spoof",
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 1,
          lengthMax = 3,
          intervalMinMs = 1L,
          intervalMaxMs = 2L,
          sniMidpointSplit = true,
          cyclicRecordLengths = intArrayOf(0, 2, 1, 3, 1),
          tcpSplitLengths = intArrayOf(2, 1, 3, 1, 32, 1),
          tcpMaxSplit = 24,
        )

      /**
       * TCP packet chunking configuration for plain non-TLS handshakes (`packets: "1-2"`).
       */
      val DEFAULT_TCP_PACKETS =
        FragmentConfig(
          profileId = "tcp_packets",
          packetsFrom = 1,
          packetsTo = 2,
          lengthMin = 14,
          lengthMax = 40,
          intervalMinMs = 2L,
          intervalMaxMs = 5L,
        )

      /**
       * Patterniha `tcp-fragment` for plain TCP (`packets: "1-1"`, `lengths: ["1"]`, `delays: ["1"]`).
       */
      val PATTERNIHA_TCP_DIRECT =
        FragmentConfig(
          profileId = "patterniha_tcp_direct",
          packetsFrom = 1,
          packetsTo = 1,
          lengthMin = 1,
          lengthMax = 2,
          intervalMinMs = 1L,
          intervalMaxMs = 1L,
          tcpSplitLengths = intArrayOf(1, 2, 1),
          tcpMaxSplit = 32,
        )

      fun fromProfileId(profileId: String): FragmentConfig {
        return when (profileId.lowercase()) {
          "aether_sni_split", "aether" -> AETHER_SNI_SPLIT
          "whitedns_byedpi", "whitedns" -> WHITEDNS_BYEDPI
          "patterniha_frag_a" -> PATTERNIHA_FRAG_A
          "patterniha_frag_b", "patterniha_ff", "patterniha_zeus" -> PATTERNIHA_FRAG_B
          "patterniha_sni_spoof", "patterniha_mmdf" -> PATTERNIHA_SNI_SPOOF
          "patterniha_tcp_direct" -> PATTERNIHA_TCP_DIRECT
          else -> DEFAULT_TLS_HELLO
        }
      }
    }
  }

  /**
   * Direct port of `sni_host_range(buf: &[u8])` from `CluvexStudio/Aether/aether/src/fragment.rs`.
   * Inspects a TLS Handshake ClientHello (`0x16 ... 0x01`) and returns the exact byte indices
   * `[start, end)` of the SNI hostname inside extension `0x0000` (server_name).
   */
  fun findTlsSniHostRange(buf: ByteArray): IntRange? {
    fun take(at: Int, n: Int): Int? {
      if (at < 0 || at + n > buf.size) return null
      var acc = 0
      for (i in 0 until n) {
        acc = (acc shl 8) or (buf[at + i].toInt() and 0xFF)
      }
      return acc
    }

    if (buf.size < 48) return null
    if ((buf[0].toInt() and 0xFF) != 0x16 || (buf[5].toInt() and 0xFF) != 0x01) {
      return null
    }
    var at = 43
    val sessionIdLen = take(at, 1) ?: return null
    at += 1 + sessionIdLen
    val cipherSuitesLen = take(at, 2) ?: return null
    at += 2 + cipherSuitesLen
    val compressionLen = take(at, 1) ?: return null
    at += 1 + compressionLen
    val extensionsLen = take(at, 2) ?: return null
    val extensionsEnd = at + 2 + extensionsLen
    at += 2

    while (at + 4 <= extensionsEnd && at + 4 <= buf.size) {
      val kind = take(at, 2) ?: return null
      val len = take(at, 2) ?: return null
      val body = at + 4
      if (kind == 0x0000) {
        val entry = body + 2
        val nameType = take(entry, 1) ?: return null
        if (nameType != 0) return null
        val hostLen = take(entry + 1, 2) ?: return null
        val hostStart = entry + 3
        if (hostLen <= 0 || hostStart + hostLen > buf.size) return null
        return hostStart until (hostStart + hostLen)
      }
      at = body + len
    }
    return null
  }

  /**
   * Sniffs the TLS ClientHello SNI hostname (`server_name` extension `0x0000`) from the first
   * client payload bytes (`destOverride: ["tls"]`), enabling `LocalV2RayProxyServer` to override
   * poisoned/cached IPs (`10.10.34.x`) or raw Cloudflare edge IPs (`104.16.x.y`) with the real domain.
   */
  fun extractTlsSniHostname(buf: ByteArray, length: Int = buf.size): String? {
    val slice = if (length < buf.size) buf.copyOfRange(0, length) else buf
    val range = findTlsSniHostRange(slice) ?: return null
    val len = range.last - range.first + 1
    if (len !in 3..253) return null
    val host = String(slice, range.first, len, Charsets.US_ASCII).trim().trimEnd('.').lowercase()
    if (!host.contains('.')) return null
    if (host.any { ch -> !(ch in 'a'..'z' || ch in '0'..'9' || ch == '.' || ch == '-') }) {
      return null
    }
    return host
  }

  /**
   * Establishes a TLS session over ANY [rawIn] and [rawOut] streams using [SSLEngine].
   * This completely avoids `SSLSocketFactory.createSocket(Socket)` on wrapper sockets,
   * fixing the Android 9 (Samsung S8) Conscrypt `FileDescriptor` crash while allowing
   * [rawOut] to be a [FragmentWriterOutputStream] or a V2Ray tunnel stream!
   */
  fun openSslEngineOverStreams(
    sslContext: SSLContext,
    rawIn: InputStream,
    rawOut: OutputStream,
    sniHost: String,
    port: Int,
    cipherSuites: List<String> = emptyList(),
    alpnProtocols: Array<String>? = null,
  ): Pair<InputStream, OutputStream> {
    val cleanHost = sniHost.trim().trimEnd('.')
    val engine =
      if (cleanHost.isNotEmpty()) {
        sslContext.createSSLEngine(cleanHost, port)
      } else {
        sslContext.createSSLEngine()
      }
    engine.useClientMode = true

    if (cipherSuites.isNotEmpty()) {
      try {
        val supported = engine.supportedCipherSuites.toSet()
        val filtered = cipherSuites.filter { it in supported }
        if (filtered.isNotEmpty()) {
          engine.enabledCipherSuites = filtered.toTypedArray()
        }
      } catch (_: Exception) {}
    }

    try {
      val params = engine.sslParameters
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N &&
        cleanHost.isNotEmpty() &&
        !cleanHost[0].isDigit()
      ) {
        params.serverNames = listOf(SNIHostName(cleanHost))
      }
      if (alpnProtocols != null && alpnProtocols.isNotEmpty()) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
          params.applicationProtocols = alpnProtocols
        } else {
          try {
            val method =
              engine.javaClass.getMethod("setApplicationProtocols", Array<String>::class.java)
            method.isAccessible = true
            method.invoke(engine, alpnProtocols)
          } catch (_: Throwable) {}
        }
      }
      engine.sslParameters = params
    } catch (_: Throwable) {}

    val session = SslEngineStreamSession(engine, rawIn, rawOut)
    session.performHandshake()
    return Pair(session.appInputStream, session.appOutputStream)
  }

  /**
   * Performs GFW-knocker's `httpupgrade` handshake (`transport/internet/httpupgrade/dialer.go`).
   */
  fun performHttpUpgrade(
    config: V2RayConfig,
    input: InputStream,
    output: OutputStream,
  ) {
    val host =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')
    val rawPath = config.path.substringBefore("?ed=").ifBlank { "/" }
    val path = if (rawPath.startsWith("/")) rawPath else "/$rawPath"

    val keyBytes = ByteArray(16).also { rng.nextBytes(it) }
    val wsKey = encodeBase64(keyBytes)

    val requestHeaders =
      "GET $path HTTP/1.1\r\n" +
        "Host: $host\r\n" +
        "Connection: Upgrade\r\n" +
        "Upgrade: websocket\r\n" +
        "Sec-WebSocket-Key: $wsKey\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "User-Agent: $GFW_KNOCKER_USER_AGENT\r\n\r\n"

    output.write(requestHeaders.toByteArray(Charsets.US_ASCII))
    output.flush()

    val headerBuf = ByteArrayOutputStream(512)
    var state = 0
    while (headerBuf.size() < 8192) {
      val b = input.read()
      if (b == -1) throw EOFException("EOF during httpupgrade handshake")
      headerBuf.write(b)
      state =
        when {
          state == 0 && b == '\r'.code -> 1
          state == 1 && b == '\n'.code -> 2
          state == 2 && b == '\r'.code -> 3
          state == 3 && b == '\n'.code -> 4
          else -> if (b == '\r'.code) 1 else 0
        }
      if (state == 4) break
    }
    val responseText = headerBuf.toString("US-ASCII")
    val firstLine = responseText.lineSequence().firstOrNull().orEmpty()
    if (!firstLine.contains(" 101 ")) {
      throw IOException("httpupgrade rejected: $firstLine")
    }
  }

  fun vlessWireVersionFor(protocol: V2RayProtocol): Byte {
    return when (protocol) {
      V2RayProtocol.MVLESS -> VLESS_VERSION_MVLESS
      V2RayProtocol.JVLESS -> VLESS_VERSION_JVLESS
      else -> VLESS_VERSION_STANDARD
    }
  }

  fun buildXrayCoreJson(config: V2RayConfig): String {
    if (config.protocol == V2RayProtocol.SERVERLESS) {
      val isFragA = config.fragmentProfile.contains("frag_a", ignoreCase = true)
      val lengthsJson = if (isFragA) """["6", "98", "1"]""" else """["0", "104", "1"]"""
      val remarks =
        when {
          config.fragmentProfile.contains("aether", ignoreCase = true) -> "CluvexStudio/Aether SNI-Split"
          config.fragmentProfile.contains("whitedns", ignoreCase = true) -> "WhiteDNS Direct Clean-IP"
          isFragA -> "Serverless-v52-fragA (@patterniha)"
          else -> "Serverless-v52-fragB (@patterniha)"
        }
      return """
        {
          "remarks": "$remarks",
          "log": { "loglevel": "warning" },
          "dns": {
            "hosts": { "cloudflare-dns.com": "challenges.cloudflare.com" },
            "servers": [
              {
                "tag": "no-filter-dns",
                "address": "https://cloudflare-dns.com/dns-query",
                "timeoutMs": 12000
              }
            ]
          },
          "outbounds": [
            {
              "tag": "tcp-fragment-tls",
              "protocol": "freedom",
              "settings": {
                "domainStrategy": "ForceIP",
                "fragment": {
                  "packets": "tlshello",
                  "length": "10-30",
                  "interval": "1-2"
                }
              },
              "streamSettings": {
                "finalmask": {
                  "tcp": [
                    { "type": "fragment", "settings": { "packets": "tlshello", "lengths": $lengthsJson, "delays": ["0"], "maxSplit": "0" } },
                    { "type": "fragment", "settings": { "packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11" } }
                  ]
                },
                "sockopt": { "tcpNoDelay": true, "dialerProxy": "fragment" }
              }
            }
          ]
        }
      """.trimIndent()
    }

    val escRemarks = escapeJson("${config.cleanTitle} [GFW-knocker/Xray-core]")
    val escProto = escapeJson(config.protocol.name.lowercase())
    val escAddr = escapeJson(config.address)
    val escAuth = escapeJson(config.authId)
    val escEnc = escapeJson(config.encryption.ifBlank { "none" })
    val escNet = escapeJson(config.network)
    val escSec = escapeJson(config.security)
    val escSni = escapeJson(config.sni)
    val escPath = escapeJson(config.path.ifBlank { "/" })
    val escHost = escapeJson(config.hostHeader.ifBlank { config.sni })

    return """
      {
        "remarks": "$escRemarks",
        "log": {
          "loglevel": "warning"
        },
        "inbounds": [
          {
            "tag": "socks-in",
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
              "auth": "noauth",
              "udp": true,
              "userLevel": 8
            },
            "sniffing": {
              "enabled": true,
              "destOverride": ["http", "tls"]
            }
          }
        ],
        "outbounds": [
          {
            "tag": "proxy",
            "protocol": "$escProto",
            "settings": {
              "address": "$escAddr",
              "port": ${config.port},
              "id": "$escAuth",
              "encryption": "$escEnc"
            },
            "streamSettings": {
              "network": "$escNet",
              "security": "$escSec",
              "tlsSettings": {
                "serverName": "$escSni",
                "allowInsecure": true,
                "fingerprint": "chrome"
              },
              "wsSettings": {
                "path": "$escPath",
                "headers": {
                  "Host": "$escHost"
                }
              },
              "sockopt": {
                "dialerProxy": "fragment",
                "tcpNoDelay": true
              }
            }
          },
          {
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {
              "domainStrategy": "AsIs",
              "fragment": {
                "packets": "tlshello",
                "length": "10-30",
                "interval": "5-12",
                "maxSplit": "10-20"
              }
            },
            "streamSettings": {
              "sockopt": {
                "tcpNoDelay": true
              }
            }
          }
        ]
      }
    """.trimIndent()
  }

  private fun escapeJson(value: String): String {
    return value
      .replace("\\", "\\\\")
      .replace("\"", "\\\"")
      .replace("\n", "\\n")
      .replace("\r", "\\r")
  }

  private const val BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  private fun encodeBase64(data: ByteArray): String {
    val sb = StringBuilder(((data.size + 2) / 3) * 4)
    var i = 0
    while (i < data.size) {
      val b0 = data[i++].toInt() and 0xFF
      val b1 = if (i < data.size) data[i++].toInt() and 0xFF else -1
      val b2 = if (i < data.size) data[i++].toInt() and 0xFF else -1

      sb.append(BASE64_ALPHABET[b0 ushr 2])
      if (b1 < 0) {
        sb.append(BASE64_ALPHABET[(b0 and 0x03) shl 4])
        sb.append("==")
      } else {
        sb.append(BASE64_ALPHABET[((b0 and 0x03) shl 4) or (b1 ushr 4)])
        if (b2 < 0) {
          sb.append(BASE64_ALPHABET[(b1 and 0x0F) shl 2])
          sb.append('=')
        } else {
          sb.append(BASE64_ALPHABET[((b1 and 0x0F) shl 2) or (b2 ushr 6)])
          sb.append(BASE64_ALPHABET[b2 and 0x3F])
        }
      }
    }
    return sb.toString()
  }

  private fun randBetween(min: Int, max: Int): Int {
    if (min >= max) return min
    return min + rng.nextInt(max - min + 1)
  }

  private fun randBetweenLong(min: Long, max: Long): Long {
    if (min >= max) return min
    val span = (max - min + 1L).toInt().coerceAtLeast(1)
    return min + rng.nextInt(span).toLong()
  }

  /**
   * FragmentWriterOutputStream supporting:
   * 1. CluvexStudio/Aether SNI Midpoint TCP Split (`sniMidpointSplit = true`):
   *    Finds the exact SNI hostname range inside the TLS ClientHello via [findTlsSniHostRange]
   *    and splits the TCP write right at the midpoint of the SNI hostname, followed by
   *    `lengthMin..lengthMax` TCP chunks.
   * 2. Patterniha deterministic TCP split (`tcpSplitLengths` e.g. `[6, 98, 1, 114, 1]` or `[104, 1, 114, 1]`).
   * 3. GFW-knocker TLS Record Splitting when `emitTlsRecordHeaders = true` (or when `cyclicRecordLengths` is tested).
   */
  class FragmentWriterOutputStream(
    out: OutputStream,
    private val fragment: FragmentConfig = FragmentConfig.DEFAULT_TLS_HELLO,
  ) : FilterOutputStream(out) {

    private var writeCount: Long = 0L

    @Synchronized
    override fun write(b: Int) {
      write(byteArrayOf(b.toByte()), 0, 1)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
      if (len <= 0) return
      writeCount++

      // Fast-path for all subsequent packets after initial handshake
      if (writeCount > 2L) {
        out.write(b, off, len)
        return
      }

      val slice =
        if (off == 0 && len == b.size) {
          b
        } else {
          b.copyOfRange(off, off + len)
        }

      if (writeCount == 1L && (slice[0].toInt() and 0xFF) == 22 && slice.size > 5) {
        // 1. Explicit TLS record header splitting when emitTlsRecordHeaders == true
        if (fragment.emitTlsRecordHeaders) {
          writeTlsRecordSplit(slice)
          return
        }

        // 2. CluvexStudio/Aether SNI Midpoint TCP Split (`sni_host_range`)
        if (fragment.sniMidpointSplit) {
          val sniRange = findTlsSniHostRange(slice)
          if (sniRange != null) {
            val mid = sniRange.first + ((sniRange.last - sniRange.first + 1) / 2)
            if (mid in 1 until slice.size) {
              out.write(slice, 0, mid)
              out.flush()
              sleepInterval()
              writeChunkedTcpSegments(slice, startOffset = mid)
              return
            }
          }
        }

        // 3. Patterniha deterministic TCP segment split (`[6, 98, 1]` or `[104, 1]`)
        if (fragment.tcpSplitLengths != null && fragment.tcpSplitLengths.isNotEmpty()) {
          writeWithDeterministicTcpSplit(slice)
          return
        }

        // 4. Default TCP segment splitting across the ClientHello
        writeChunkedTcpSegments(slice, startOffset = 0)
        return
      }

      // Non-TLS or 2nd packet chunking
      if (fragment.packetsFrom != 0 &&
        writeCount in fragment.packetsFrom..fragment.packetsTo
      ) {
        if (fragment.tcpSplitLengths != null && fragment.tcpSplitLengths.isNotEmpty()) {
          writeWithDeterministicTcpSplit(slice)
        } else {
          writeChunkedTcpSegments(slice, startOffset = 0)
        }
        return
      }

      out.write(slice)
    }

    private fun writeChunkedTcpSegments(slice: ByteArray, startOffset: Int) {
      var from = startOffset
      var splits = 0
      val maxSplits = if (fragment.tcpMaxSplit > 0) fragment.tcpMaxSplit else 18
      while (from < slice.size) {
        if (splits >= maxSplits) {
          out.write(slice, from, slice.size - from)
          out.flush()
          break
        }
        val chunkLen = randBetween(fragment.lengthMin, fragment.lengthMax).coerceAtLeast(1)
        val to = minOf(from + chunkLen, slice.size)
        out.write(slice, from, to - from)
        out.flush()
        from = to
        splits++
        if (from < slice.size) {
          sleepInterval()
        }
      }
    }

    private fun writeWithDeterministicTcpSplit(payload: ByteArray) {
      val splitLens = fragment.tcpSplitLengths ?: return
      val maxSplits = if (fragment.tcpMaxSplit > 0) fragment.tcpMaxSplit else 14
      var offset = 0
      var splitsDone = 0
      while (offset < payload.size) {
        if (splitsDone >= maxSplits) {
          out.write(payload, offset, payload.size - offset)
          out.flush()
          break
        }
        val chunkLen = splitLens[splitsDone % splitLens.size].coerceAtLeast(1)
        val end = minOf(offset + chunkLen, payload.size)
        out.write(payload, offset, end - offset)
        out.flush()
        offset = end
        splitsDone++
        if (offset < payload.size) {
          sleepInterval()
        }
      }
    }

    private fun writeTlsRecordSplit(slice: ByteArray) {
      val recordPayloadLen = ((slice[3].toInt() and 0xFF) shl 8) or (slice[4].toInt() and 0xFF)
      val recordLen = 5 + recordPayloadLen
      if (slice.size < recordLen || recordPayloadLen <= 0) {
        out.write(slice)
        return
      }
      val data = slice.copyOfRange(5, recordLen)
      val cyclic = fragment.cyclicRecordLengths
      var from = 0
      var cycleIdx = 0
      while (from < data.size) {
        val requestedLen =
          if (cyclic != null && cyclic.isNotEmpty()) {
            cyclic[cycleIdx++ % cyclic.size].coerceAtLeast(0)
          } else {
            randBetween(fragment.lengthMin, fragment.lengthMax).coerceAtLeast(1)
          }
        val to = minOf(from + requestedLen, data.size)
        val l = to - from
        val rec = ByteArray(5 + l)
        rec[0] = slice[0]
        rec[1] = slice[1]
        rec[2] = slice[2]
        rec[3] = ((l ushr 8) and 0xFF).toByte()
        rec[4] = (l and 0xFF).toByte()
        if (l > 0) {
          System.arraycopy(data, from, rec, 5, l)
        }
        out.write(rec)
        out.flush()
        from = to
        if (from < data.size) {
          sleepInterval()
        }
      }
      if (slice.size > recordLen) {
        out.write(slice, recordLen, slice.size - recordLen)
        out.flush()
      }
    }

    private fun sleepInterval() {
      val sleepMs = randBetweenLong(fragment.intervalMinMs, fragment.intervalMaxMs)
      if (sleepMs > 0L) {
        try {
          Thread.sleep(sleepMs)
        } catch (_: InterruptedException) {}
      }
    }
  }

  /**
   * Pure `SSLEngine`-backed stream session that runs TLS 1.2/1.3 over arbitrary [rawIn] and [rawOut]
   * without touching `java.net.Socket` or `FileDescriptor`.
   */
  private class SslEngineStreamSession(
    private val engine: SSLEngine,
    private val rawIn: InputStream,
    private val rawOut: OutputStream,
  ) {
    private val session = engine.session
    private val wrapLock = Any()
    private var netInBuf = ByteBuffer.allocate(maxOf(session.packetBufferSize, 65536))
    private var netOutBuf = ByteBuffer.allocate(maxOf(session.packetBufferSize, 65536))
    private var appInBuf = ByteBuffer.allocate(maxOf(session.applicationBufferSize, 65536))
    private val readBuffer = ByteArray(32768)

    init {
      netInBuf.flip()
      appInBuf.flip()
    }

    private fun wrapEmptyHandshakePacket(): SSLEngineResult.HandshakeStatus {
      synchronized(wrapLock) {
        val emptyApp = ByteBuffer.allocate(0)
        while (true) {
          netOutBuf.clear()
          val res = engine.wrap(emptyApp, netOutBuf)
          when (res.status) {
            SSLEngineResult.Status.OK -> {
              netOutBuf.flip()
              if (netOutBuf.hasRemaining()) {
                val bytes = ByteArray(netOutBuf.remaining())
                netOutBuf.get(bytes)
                rawOut.write(bytes)
              }
              rawOut.flush()
              return res.handshakeStatus
            }
            SSLEngineResult.Status.BUFFER_OVERFLOW -> {
              netOutBuf = ByteBuffer.allocate(netOutBuf.capacity() * 2)
            }
            else -> throw SSLException("SSLEngine wrap status: ${res.status}")
          }
        }
      }
    }

    fun performHandshake() {
      engine.beginHandshake()
      var status = engine.handshakeStatus
      var loops = 0

      while (status != SSLEngineResult.HandshakeStatus.FINISHED &&
        status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
      ) {
        if (++loops > 256) {
          throw SSLException("TLS handshake exceeded max steps")
        }
        when (status) {
          SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
            status = wrapEmptyHandshakePacket()
          }

          SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
            if (!netInBuf.hasRemaining()) {
              if (!fillNetInBuffer()) {
                throw EOFException("EOF during TLS handshake unwrap")
              }
            }
            appInBuf.compact()
            val res = engine.unwrap(netInBuf, appInBuf)
            appInBuf.flip()
            status = res.handshakeStatus
            when (res.status) {
              SSLEngineResult.Status.OK -> {}
              SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                if (!fillNetInBuffer()) {
                  throw EOFException("EOF on TLS BUFFER_UNDERFLOW")
                }
              }
              SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                val bigger = ByteBuffer.allocate(appInBuf.capacity() * 2)
                bigger.put(appInBuf)
                bigger.flip()
                appInBuf = bigger
              }
              SSLEngineResult.Status.CLOSED -> throw EOFException("TLS closed during handshake")
              null -> throw SSLException("Null SSLEngine status")
            }
          }

          SSLEngineResult.HandshakeStatus.NEED_TASK -> {
            var task = engine.delegatedTask
            while (task != null) {
              task.run()
              task = engine.delegatedTask
            }
            status = engine.handshakeStatus
          }

          else -> status = engine.handshakeStatus
        }
      }
    }

    private fun fillNetInBuffer(): Boolean {
      netInBuf.compact()
      if (netInBuf.remaining() < 16384) {
        netInBuf.flip()
        val bigger = ByteBuffer.allocate(netInBuf.capacity() * 2)
        bigger.put(netInBuf)
        netInBuf = bigger
      }
      val n = rawIn.read(readBuffer, 0, minOf(readBuffer.size, netInBuf.remaining()))
      if (n <= 0) {
        netInBuf.flip()
        return false
      }
      netInBuf.put(readBuffer, 0, n)
      netInBuf.flip()
      return true
    }

    val appInputStream: InputStream =
      object : InputStream() {
        @Synchronized
        override fun read(): Int {
          val one = ByteArray(1)
          val n = read(one, 0, 1)
          return if (n == -1) -1 else (one[0].toInt() and 0xFF)
        }

        @Synchronized
        override fun read(b: ByteArray, off: Int, len: Int): Int {
          if (len == 0) return 0
          while (!appInBuf.hasRemaining()) {
            if (!netInBuf.hasRemaining()) {
              if (!fillNetInBuffer()) return -1
            }
            appInBuf.compact()
            val res = engine.unwrap(netInBuf, appInBuf)
            appInBuf.flip()
            if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
              var task = engine.delegatedTask
              while (task != null) {
                task.run()
                task = engine.delegatedTask
              }
            }
            if (engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
              wrapEmptyHandshakePacket()
            }
            if (appInBuf.hasRemaining()) break
            when (res.status) {
              SSLEngineResult.Status.OK -> {}
              SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                if (!fillNetInBuffer()) return -1
              }
              SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                val bigger = ByteBuffer.allocate(appInBuf.capacity() * 2)
                bigger.put(appInBuf)
                bigger.flip()
                appInBuf = bigger
              }
              SSLEngineResult.Status.CLOSED -> return -1
              null -> return -1
            }
          }
          val toCopy = minOf(len, appInBuf.remaining())
          appInBuf.get(b, off, toCopy)
          return toCopy
        }

        override fun close() {
          try {
            rawIn.close()
          } catch (_: Exception) {}
        }
      }

    val appOutputStream: OutputStream =
      object : OutputStream() {
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          synchronized(wrapLock) {
            val src = ByteBuffer.wrap(b, off, len)
            while (src.hasRemaining()) {
              netOutBuf.clear()
              val res = engine.wrap(src, netOutBuf)
              when (res.status) {
                SSLEngineResult.Status.OK -> {
                  netOutBuf.flip()
                  if (netOutBuf.hasRemaining()) {
                    val outBytes = ByteArray(netOutBuf.remaining())
                    netOutBuf.get(outBytes)
                    rawOut.write(outBytes)
                  }
                }
                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                  netOutBuf = ByteBuffer.allocate(netOutBuf.capacity() * 2)
                }
                else -> throw IOException("SSLEngine write failed: ${res.status}")
              }
            }
          }
        }

        override fun flush() {
          synchronized(wrapLock) {
            rawOut.flush()
          }
        }

        override fun close() {
          try {
            engine.closeOutbound()
          } catch (_: Exception) {}
          try {
            rawOut.close()
          } catch (_: Exception) {}
        }
      }
  }
}
