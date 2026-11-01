package com.example.vpn

import android.util.Base64
import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.system.measureNanoTime

/**
 * Real V2Ray Outbound Protocol Client supporting:
 * - Protocols: VLESS (v0) and Trojan
 * - Transports: Raw TCP and RFC 6455 WebSocket (ws) / HTTPUpgrade
 * - Security: None and TLS (with custom SNI and permissive certificate trust for self-signed V2Ray nodes)
 */
object V2RayOutboundClient {

  private val secureRandom = SecureRandom()

  private val permissiveSslContext: SSLContext by lazy {
    val trustAll =
      arrayOf<TrustManager>(
        object : X509TrustManager {
          override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
      )
    SSLContext.getInstance("TLS").apply {
      init(null, trustAll, secureRandom)
    }
  }

  class TunnelConnection(
    val underlyingSocket: Socket,
    val inputStream: InputStream,
    val outputStream: OutputStream,
  ) : AutoCloseable {
    override fun close() {
      try {
        outputStream.close()
      } catch (_: Exception) {}
      try {
        inputStream.close()
      } catch (_: Exception) {}
      try {
        underlyingSocket.close()
      } catch (_: Exception) {}
    }
  }

  /**
   * Returns true if this config uses a protocol/transport combination supported by the built-in V2Ray engine.
   */
  fun isSupportedByEngine(config: V2RayConfig): Boolean {
    if (config.protocol != V2RayProtocol.VLESS && config.protocol != V2RayProtocol.TROJAN) {
      return false
    }
    val net = config.network.lowercase()
    if (net != "tcp" && net != "ws" && net != "httpupgrade") {
      return false
    }
    val sec = config.security.lowercase()
    // Exclude "reality" since X25519 uTLS fingerprint forging requires native Go/BoringSSL
    if (sec != "none" && sec != "tls" && sec != "") {
      return false
    }
    if (config.protocol == V2RayProtocol.VLESS && parseUuidBytes(config.authId) == null) {
      return false
    }
    return true
  }

  /**
   * Tests a V2Ray node by opening a real V2Ray protocol tunnel to `cp.cloudflare.com:80`
   * and sending `GET /generate_204 HTTP/1.1` through the proxy tunnel.
   * Returns the measured round-trip delay in milliseconds if and only if valid HTTP response returns.
   */
  fun measureRealProxyDelay(
    config: V2RayConfig,
    timeoutMs: Int = 2200,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    if (!isSupportedByEngine(config)) return null
    return try {
      var latencyMs = -1L
      val elapsedNanos =
        measureNanoTime {
          openTunnel(
            config = config,
            targetHost = "cp.cloudflare.com",
            targetPort = 80,
            timeoutMs = timeoutMs,
            protector = protector,
          ).use { conn ->
            val probeRequest =
              "GET /generate_204 HTTP/1.1\r\n" +
                "Host: cp.cloudflare.com\r\n" +
                "User-Agent: curl/8.0\r\n" +
                "Connection: close\r\n\r\n"
            conn.outputStream.write(probeRequest.toByteArray(Charsets.US_ASCII))
            conn.outputStream.flush()

            val buffer = ByteArray(128)
            val read = conn.inputStream.read(buffer)
            if (read <= 0) throw IOException("Empty response from proxy")
            val statusLine = String(buffer, 0, read, Charsets.US_ASCII)
            if (!statusLine.startsWith("HTTP/1.1 204") &&
              !statusLine.startsWith("HTTP/1.0 204") &&
              !statusLine.startsWith("HTTP/1.1 200") &&
              !statusLine.startsWith("HTTP/1.1 301") &&
              !statusLine.startsWith("HTTP/1.1 302")
            ) {
              throw IOException("Unexpected HTTP probe response: ${statusLine.take(30)}")
            }
          }
        }
      latencyMs = (elapsedNanos / 1_000_000L).coerceAtLeast(1L)
      latencyMs
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Establishes an outbound V2Ray tunnel to [targetHost]:[targetPort] through [config].
   */
  fun openTunnel(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 6000,
    protector: ((Socket) -> Boolean)? = null,
  ): TunnelConnection {
    val rawSocket = Socket()
    try {
      protector?.invoke(rawSocket)
      rawSocket.tcpNoDelay = true
      rawSocket.soTimeout = timeoutMs
      rawSocket.connect(InetSocketAddress(config.address, config.port), timeoutMs)

      val transportSocket: Socket =
        if (config.security.equals("tls", ignoreCase = true)) {
          wrapTlsSocket(rawSocket, config, timeoutMs)
        } else {
          rawSocket
        }

      var transportIn: InputStream = BufferedInputStream(transportSocket.getInputStream(), 16384)
      var transportOut: OutputStream = transportSocket.getOutputStream()

      if (config.network.equals("ws", ignoreCase = true) ||
        config.network.equals("httpupgrade", ignoreCase = true)
      ) {
        val isWs = config.network.equals("ws", ignoreCase = true)
        performWebSocketUpgrade(config, transportIn, transportOut)
        if (isWs) {
          transportIn = WebSocketFrameInputStream(transportIn)
          transportOut = WebSocketFrameOutputStream(transportOut)
        }
      }

      return when (config.protocol) {
        V2RayProtocol.VLESS ->
          setupVlessStream(transportSocket, transportIn, transportOut, config, targetHost, targetPort)
        V2RayProtocol.TROJAN ->
          setupTrojanStream(transportSocket, transportIn, transportOut, config, targetHost, targetPort)
        else -> throw IOException("Unsupported protocol: ${config.protocol}")
      }
    } catch (e: Exception) {
      try {
        rawSocket.close()
      } catch (_: Exception) {}
      throw e
    }
  }

  private fun wrapTlsSocket(
    rawSocket: Socket,
    config: V2RayConfig,
    timeoutMs: Int,
  ): SSLSocket {
    val sniHost =
      config.sni
        .ifBlank { config.hostHeader }
        .ifBlank { config.address }
        .trim()

    val sslSocket =
      permissiveSslContext.socketFactory.createSocket(
        rawSocket,
        sniHost,
        config.port,
        true,
      ) as SSLSocket

    sslSocket.soTimeout = timeoutMs
    try {
      if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N &&
        sniHost.isNotEmpty() &&
        !sniHost[0].isDigit()
      ) {
        val params = sslSocket.sslParameters
        params.serverNames = listOf(SNIHostName(sniHost))
        sslSocket.sslParameters = params
      }
    } catch (_: Exception) {}

    sslSocket.startHandshake()
    return sslSocket
  }

  private fun performWebSocketUpgrade(
    config: V2RayConfig,
    input: InputStream,
    output: OutputStream,
  ) {
    val wsHost =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .trim()
    val rawPath = config.path.ifBlank { "/" }
    val wsPath = if (rawPath.startsWith("/")) rawPath else "/$rawPath"

    val keyBytes = ByteArray(16).also { secureRandom.nextBytes(it) }
    val wsKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)

    val requestHeaders =
      "GET $wsPath HTTP/1.1\r\n" +
        "Host: $wsHost\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: $wsKey\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "User-Agent: Mozilla/5.0\r\n\r\n"

    output.write(requestHeaders.toByteArray(Charsets.US_ASCII))
    output.flush()

    // Read HTTP response headers until \r\n\r\n
    val headerBuf = ByteArrayOutputStream(512)
    var state = 0
    while (headerBuf.size() < 8192) {
      val b = input.read()
      if (b == -1) throw EOFException("EOF during WebSocket handshake")
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
    if (!firstLine.contains("101")) {
      throw IOException("WebSocket upgrade rejected: $firstLine")
    }
  }

  private fun setupVlessStream(
    socket: Socket,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): TunnelConnection {
    val uuidBytes =
      parseUuidBytes(config.authId) ?: throw IOException("Invalid VLESS UUID: ${config.authId}")

    val header = ByteArrayOutputStream(64)
    header.write(0x00) // Version 0
    header.write(uuidBytes) // 16-byte UUID
    header.write(0x00) // Addons length = 0
    header.write(0x01) // Command = 0x01 (TCP)
    header.write((targetPort ushr 8) and 0xFF) // Port high byte
    header.write(targetPort and 0xFF) // Port low byte

    writeVlessAddress(header, targetHost)
    val headerBytes = header.toByteArray()

    // Send VLESS header along with first payload write (or immediately)
    val vlessOut =
      object : FilterOutputStream(output) {
        private var headerSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (!headerSent) {
            headerSent = true
            val combined = ByteArray(headerBytes.size + len)
            System.arraycopy(headerBytes, 0, combined, 0, headerBytes.size)
            System.arraycopy(b, off, combined, headerBytes.size, len)
            out.write(combined)
          } else {
            out.write(b, off, len)
          }
        }
      }

    // Consume VLESS 2-byte response header [version, addon_len, ...addons] on first read
    val vlessIn =
      object : FilterInputStream(input) {
        private var responseHeaderRead = false

        @Synchronized
        private fun ensureHeader() {
          if (!responseHeaderRead) {
            responseHeaderRead = true
            val ver = `in`.read()
            if (ver == -1) throw EOFException("VLESS EOF before response header")
            val addonLen = `in`.read()
            if (addonLen == -1) throw EOFException("VLESS EOF reading addon length")
            var remaining = addonLen
            while (remaining > 0) {
              val skipped = `in`.skip(remaining.toLong()).toInt()
              if (skipped <= 0) {
                if (`in`.read() == -1) throw EOFException("VLESS EOF skipping addons")
                remaining--
              } else {
                remaining -= skipped
              }
            }
          }
        }

        override fun read(): Int {
          ensureHeader()
          return `in`.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
          ensureHeader()
          return `in`.read(b, off, len)
        }
      }

    return TunnelConnection(socket, vlessIn, vlessOut)
  }

  private fun setupTrojanStream(
    socket: Socket,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): TunnelConnection {
    val passwordHashHex = sha224Hex(config.authId)
    val header = ByteArrayOutputStream(128)
    header.write(passwordHashHex.toByteArray(Charsets.US_ASCII))
    header.write(byteArrayOf(0x0D, 0x0A))
    header.write(0x01) // CONNECT
    writeSocks5Address(header, targetHost)
    header.write((targetPort ushr 8) and 0xFF)
    header.write(targetPort and 0xFF)
    header.write(byteArrayOf(0x0D, 0x0A))
    val headerBytes = header.toByteArray()

    val trojanOut =
      object : FilterOutputStream(output) {
        private var headerSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (!headerSent) {
            headerSent = true
            val combined = ByteArray(headerBytes.size + len)
            System.arraycopy(headerBytes, 0, combined, 0, headerBytes.size)
            System.arraycopy(b, off, combined, headerBytes.size, len)
            out.write(combined)
          } else {
            out.write(b, off, len)
          }
        }
      }

    return TunnelConnection(socket, input, trojanOut)
  }

  private fun writeVlessAddress(out: ByteArrayOutputStream, host: String) {
    val ipv4Parts = host.split(".")
    if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() in 0..255 }) {
      out.write(0x01) // IPv4
      for (part in ipv4Parts) {
        out.write(part.toInt())
      }
    } else {
      val domainBytes = host.toByteArray(Charsets.UTF_8)
      out.write(0x02) // Domain
      out.write(domainBytes.size)
      out.write(domainBytes)
    }
  }

  private fun writeSocks5Address(out: ByteArrayOutputStream, host: String) {
    val ipv4Parts = host.split(".")
    if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() in 0..255 }) {
      out.write(0x01) // IPv4
      for (part in ipv4Parts) {
        out.write(part.toInt())
      }
    } else {
      val domainBytes = host.toByteArray(Charsets.UTF_8)
      out.write(0x03) // Domain in SOCKS5/Trojan
      out.write(domainBytes.size)
      out.write(domainBytes)
    }
  }

  private fun parseUuidBytes(uuidStr: String): ByteArray? {
    val hex = uuidStr.trim().replace("-", "")
    if (hex.length != 32) return null
    val bytes = ByteArray(16)
    return try {
      for (i in 0 until 16) {
        val index = i * 2
        bytes[i] = hex.substring(index, index + 2).toInt(16).toByte()
      }
      bytes
    } catch (_: Exception) {
      null
    }
  }

  private fun sha224Hex(input: String): String {
    val md = MessageDigest.getInstance("SHA-224")
    val digest = md.digest(input.toByteArray(Charsets.UTF_8))
    val sb = StringBuilder(56)
    for (b in digest) {
      sb.append(String.format("%02x", b))
    }
    return sb.toString()
  }

  /**
   * RFC 6455 WebSocket Binary Frame OutputStream (client-to-server frames must be masked).
   */
  private class WebSocketFrameOutputStream(out: OutputStream) : FilterOutputStream(out) {
    private val rng = SecureRandom()

    @Synchronized
    override fun write(b: Int) {
      write(byteArrayOf(b.toByte()), 0, 1)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
      if (len <= 0) return
      val maskKey = ByteArray(4).also { rng.nextBytes(it) }
      val frame = ByteArrayOutputStream(len + 14)
      frame.write(0x82) // FIN + Binary frame (0x02)
      when {
        len <= 125 -> frame.write(0x80 or len)
        len <= 65535 -> {
          frame.write(0x80 or 126)
          frame.write((len ushr 8) and 0xFF)
          frame.write(len and 0xFF)
        }
        else -> {
          frame.write(0x80 or 127)
          val longLen = len.toLong()
          for (shift in 56 downTo 0 step 8) {
            frame.write(((longLen ushr shift) and 0xFF).toInt())
          }
        }
      }
      frame.write(maskKey)
      val maskedPayload = ByteArray(len)
      for (i in 0 until len) {
        maskedPayload[i] = (b[off + i].toInt() xor maskKey[i and 3].toInt()).toByte()
      }
      frame.write(maskedPayload)
      out.write(frame.toByteArray())
    }
  }

  /**
   * RFC 6455 WebSocket Frame InputStream.
   */
  private class WebSocketFrameInputStream(input: InputStream) : FilterInputStream(input) {
    private val dataIn = DataInputStream(input)
    private var currentPayload: ByteArray = ByteArray(0)
    private var currentOffset = 0

    @Synchronized
    override fun read(): Int {
      val single = ByteArray(1)
      val n = read(single, 0, 1)
      return if (n == -1) -1 else (single[0].toInt() and 0xFF)
    }

    @Synchronized
    override fun read(b: ByteArray, off: Int, len: Int): Int {
      if (len == 0) return 0
      while (currentOffset >= currentPayload.size) {
        if (!readNextFrame()) return -1
      }
      val available = currentPayload.size - currentOffset
      val toCopy = minOf(len, available)
      System.arraycopy(currentPayload, currentOffset, b, off, toCopy)
      currentOffset += toCopy
      return toCopy
    }

    private fun readNextFrame(): Boolean {
      while (true) {
        val b0 = `in`.read()
        if (b0 == -1) return false
        val opcode = b0 and 0x0F
        val b1 = `in`.read()
        if (b1 == -1) return false
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()

        if (payloadLen == 126L) {
          payloadLen = dataIn.readUnsignedShort().toLong()
        } else if (payloadLen == 127L) {
          payloadLen = dataIn.readLong()
        }

        val maskKey =
          if (masked) {
            ByteArray(4).also { dataIn.readFully(it) }
          } else {
            null
          }

        if (payloadLen > 4 * 1024 * 1024) {
          throw IOException("WebSocket frame too large: $payloadLen")
        }

        val payload = ByteArray(payloadLen.toInt())
        dataIn.readFully(payload)
        if (maskKey != null) {
          for (i in payload.indices) {
            payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
          }
        }

        when (opcode) {
          0x08 -> return false // Connection close frame
          0x09 -> {
            // Ping frame -> ignore or continue
            continue
          }
          0x0A -> continue // Pong frame
          0x00, 0x01, 0x02 -> {
            if (payload.isNotEmpty()) {
              currentPayload = payload
              currentOffset = 0
              return true
            }
          }
        }
      }
    }
  }
}
