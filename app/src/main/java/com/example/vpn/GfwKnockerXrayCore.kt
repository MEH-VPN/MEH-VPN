package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress
import java.security.SecureRandom
import org.json.JSONArray
import org.json.JSONObject

/**
 * Core engine implementation of https://github.com/GFW-knocker/Xray-core (v26.10.3-mahsa-r2):
 *
 * 1. TLS Record Splitting & TCP Fragmentation (`proxy/freedom/freedom.go` -> `FragmentWriter`):
 *    - Intercepts outbound TLS ClientHello records (`0x16 0x03 ...`) and splits the handshake
 *      payload (including the plaintext SNI extension) into multiple smaller valid TLS records
 *      (`10-30` bytes each) transmitted across separate TCP segments with `5-12ms` intervals.
 *    - Defeats SNI Deep Packet Inspection (DPI) on Iranian mobile/fixed ISPs (MCI, Irancell, TCI).
 * 2. GFW-knocker Custom Protocols:
 *    - `mvless` (`proxy/mvless/encoding/encoding.go`): Version byte `150` (`0x96`)
 *    - `jvless` (`proxy/jvless/outbound/outbound.go`): Swaps first request/response version byte `0x00 <-> 0x78`
 *    - `vless` (Version `0x00`) & `trojan`
 * 3. GFW-knocker `httpupgrade` & `ws` Transports (`transport/internet/httpupgrade/dialer.go`):
 *    - Uses GFW-knocker's Chrome/138 User-Agent and `http/1.1` ALPN negotiation.
 */
object GfwKnockerXrayCore {

  const val CORE_VERSION = "Mahsa-XrayCore v26.10.3-mahsa-r2 (GFW-knocker/Xray-core)"

  const val GFW_KNOCKER_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

  const val VLESS_VERSION_STANDARD: Byte = 0x00
  const val VLESS_VERSION_MVLESS: Byte = 150.toByte() // 0x96 in GFW-knocker/Xray-core/proxy/mvless
  const val VLESS_VERSION_JVLESS: Byte = 0x78.toByte() // 'x' in GFW-knocker/Xray-core/proxy/jvless

  private val rng = SecureRandom()

  data class FragmentConfig(
    val packetsFrom: Int = 0,
    val packetsTo: Int = 1,
    val lengthMin: Int = 10,
    val lengthMax: Int = 30,
    val intervalMinMs: Long = 5L,
    val intervalMaxMs: Long = 12L,
    val batchMin: Int = 1,
    val batchMax: Int = 2,
    val emptyRecordMinor: Int = 0,
  ) {
    companion object {
      /**
       * Default `tlshello` record-splitting configuration from GFW-knocker/Xray-core (`packets: "tlshello"`).
       */
      val DEFAULT_TLS_HELLO =
        FragmentConfig(
          packetsFrom = 0,
          packetsTo = 1,
          lengthMin = 10,
          lengthMax = 30,
          intervalMinMs = 5L,
          intervalMaxMs = 12L,
          batchMin = 1,
          batchMax = 2,
          emptyRecordMinor = 0,
        )

      /**
       * TCP packet chunking configuration for plain non-TLS handshakes (`packets: "1-2"`).
       */
      val DEFAULT_TCP_PACKETS =
        FragmentConfig(
          packetsFrom = 1,
          packetsTo = 2,
          lengthMin = 14,
          lengthMax = 40,
          intervalMinMs = 4L,
          intervalMaxMs = 10L,
        )
    }
  }

  /**
   * Wraps a connected & VPN-protected TCP [Socket] so that Android's Conscrypt `SSLSocket`
   * uses `ConscryptEngineSocket` over [FragmentWriterOutputStream] instead of bypassing Java streams
   * via native `SSL_set_fd`.
   */
  fun wrapSocketWithFragmentWriter(
    rawSocket: Socket,
    fragmentConfig: FragmentConfig = FragmentConfig.DEFAULT_TLS_HELLO,
  ): Socket {
    return FragmentedTransportSocket(rawSocket, fragmentConfig)
  }

  /**
   * Performs GFW-knocker's `httpupgrade` handshake (`transport/internet/httpupgrade/dialer.go`).
   * Unlike WebSocket (`ws`), `httpupgrade` sends an HTTP `Upgrade: websocket` request and receives
   * `101 Switching Protocols`, then streams raw unframed VLESS/Trojan bytes over the connection.
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

  /**
   * Returns the VLESS wire version byte for [protocol] per `GFW-knocker/Xray-core`:
   * - `VLESS`: `0x00`
   * - `MVLESS`: `150` (`0x96`)
   * - `JVLESS`: `0x78` (`'x'`)
   */
  fun vlessWireVersionFor(protocol: V2RayProtocol): Byte {
    return when (protocol) {
      V2RayProtocol.MVLESS -> VLESS_VERSION_MVLESS
      V2RayProtocol.JVLESS -> VLESS_VERSION_JVLESS
      else -> VLESS_VERSION_STANDARD
    }
  }

  /**
   * Builds a complete `GFW-knocker/Xray-core` JSON config (`v26.10.3-mahsa-r2`)
   * including the `fragment` freedom outbound and `sockopt.dialerProxy = "fragment"`.
   */
  fun buildXrayCoreJson(config: V2RayConfig): String {
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
              },
              "noises": [
                {
                  "type": "rand",
                  "packet": "10-20",
                  "delay": "10-16",
                  "applyTo": "ip"
                }
              ]
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
   * Direct port of `FragmentWriter` from `github.com/GFW-knocker/Xray-core/proxy/freedom/freedom.go`.
   *
   * When `packetsFrom == 0 && packetsTo == 1` (`"tlshello"`), splits the first TLS Handshake
   * record (`b[0] == 22 && b[1] == 3`) into multiple valid TLS Handshake records of `lengthMin..lengthMax`
   * bytes so that SNI inspection middleboxes cannot reassemble the ClientHello in a single record.
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
      if (writeCount > 3L) {
        out.write(b, off, len)
        return
      }

      val slice =
        if (off == 0 && len == b.size) {
          b
        } else {
          b.copyOfRange(off, off + len)
        }

      // Case 1: GFW-knocker "tlshello" TLS Record Splitting (PacketsFrom == 0 && PacketsTo == 1)
      if (fragment.packetsFrom == 0 && fragment.packetsTo == 1) {
        if (writeCount != 1L || slice.size <= 5 || (slice[0].toInt() and 0xFF) != 22) {
          out.write(slice)
          return
        }
        val recordPayloadLen = ((slice[3].toInt() and 0xFF) shl 8) or (slice[4].toInt() and 0xFF)
        val recordLen = 5 + recordPayloadLen
        if (slice.size < recordLen || recordPayloadLen <= 0) {
          out.write(slice)
          return
        }

        val data = slice.copyOfRange(5, recordLen)
        val nQueue = randBetween(fragment.batchMin, fragment.batchMax).coerceAtLeast(0)
        val queue = ByteArrayOutputStream(recordLen + 128)
        var cQueue = 0

        if (fragment.emptyRecordMinor != 0) {
          queue.write(byteArrayOf(22, 3, fragment.emptyRecordMinor.toByte(), 0, 0))
        }

        var from = 0
        while (from < data.size) {
          val chunkLen = randBetween(fragment.lengthMin, fragment.lengthMax).coerceAtLeast(1)
          val to = minOf(from + chunkLen, data.size)
          val l = to - from

          // Construct a valid 5-byte TLS Handshake record header for this fragment
          queue.write(slice[0].toInt()) // 0x16 (22 = Handshake)
          queue.write(slice[1].toInt()) // 0x03 (TLS major)
          queue.write(slice[2].toInt()) // TLS minor (e.g. 0x01 / 0x03)
          queue.write((l ushr 8) and 0xFF)
          queue.write(l and 0xFF)
          queue.write(data, from, l)

          from = to

          if (cQueue < nQueue && from < data.size) {
            cQueue++
          } else {
            val batchBytes = queue.toByteArray()
            if (batchBytes.isNotEmpty()) {
              out.write(batchBytes)
              out.flush()
              val sleepMs = randBetweenLong(fragment.intervalMinMs, fragment.intervalMaxMs)
              if (sleepMs > 0L && from < data.size) {
                try {
                  Thread.sleep(sleepMs)
                } catch (_: InterruptedException) {}
              }
            }
            queue.reset()
            cQueue = 0
          }
        }

        if (queue.size() > 0) {
          out.write(queue.toByteArray())
          out.flush()
        }

        if (slice.size > recordLen) {
          out.write(slice, recordLen, slice.size - recordLen)
          out.flush()
        }
        return
      }

      // Case 2: GFW-knocker TCP Packet Chunking (PacketsFrom..PacketsTo)
      if (fragment.packetsFrom != 0 &&
        (writeCount < fragment.packetsFrom || writeCount > fragment.packetsTo)
      ) {
        out.write(slice)
        return
      }

      var from = 0
      while (from < slice.size) {
        val chunkLen = randBetween(fragment.lengthMin, fragment.lengthMax).coerceAtLeast(1)
        val to = minOf(from + chunkLen, slice.size)
        out.write(slice, from, to - from)
        out.flush()
        from = to
        if (from < slice.size) {
          val sleepMs = randBetweenLong(fragment.intervalMinMs, fragment.intervalMaxMs)
          if (sleepMs > 0L) {
            try {
              Thread.sleep(sleepMs)
            } catch (_: InterruptedException) {}
          }
        }
      }
    }
  }

  /**
   * Unconnected [Socket] adapter delegating I/O to [delegate] through [FragmentWriterOutputStream].
   * Because the superclass [Socket] has no raw OS `FileDescriptor`, Android's Conscrypt
   * uses `ConscryptEngineSocket` (`SSLEngine`) and writes the TLS ClientHello through
   * [fragmentedOut], guaranteeing that GFW-knocker TLS Record Splitting is applied on Android 5–16.
   */
  private class FragmentedTransportSocket(
    private val delegate: Socket,
    fragmentConfig: FragmentConfig,
  ) : Socket() {
    private val fragmentedOut = FragmentWriterOutputStream(delegate.getOutputStream(), fragmentConfig)

    override fun getInputStream(): InputStream = delegate.getInputStream()
    override fun getOutputStream(): OutputStream = fragmentedOut
    override fun isConnected(): Boolean = delegate.isConnected
    override fun isBound(): Boolean = delegate.isBound
    override fun isClosed(): Boolean = delegate.isClosed
    override fun getInetAddress(): InetAddress? = delegate.inetAddress
    override fun getLocalAddress(): InetAddress = delegate.localAddress
    override fun getPort(): Int = delegate.port
    override fun getLocalPort(): Int = delegate.localPort
    override fun getRemoteSocketAddress(): SocketAddress? = delegate.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress? = delegate.localSocketAddress
    override fun setSoTimeout(timeout: Int) {
      delegate.soTimeout = timeout
    }
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun setTcpNoDelay(on: Boolean) {
      delegate.tcpNoDelay = on
    }
    override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay
    override fun setKeepAlive(on: Boolean) {
      delegate.keepAlive = on
    }
    override fun getKeepAlive(): Boolean = delegate.keepAlive
    @Synchronized
    override fun close() {
      try {
        fragmentedOut.flush()
      } catch (_: Exception) {}
      delegate.close()
    }
  }
}
