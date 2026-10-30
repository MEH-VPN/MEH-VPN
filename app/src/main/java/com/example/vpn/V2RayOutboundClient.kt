package com.example.vpn

import android.net.VpnService
import android.os.Build
import android.util.Base64
import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.system.measureTimeMillis

/**
 * Represents an established, bi-directional V2Ray stream (VLESS or Trojan over TCP/TLS/WebSocket)
 * connected to a remote target [targetHost]:[targetPort].
 */
class V2RayTunnelStream(
    private val underlyingSocket: Socket,
    val input: InputStream,
    val output: OutputStream
) : Closeable {
    override fun close() {
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { underlyingSocket.close() }
    }
}

object V2RayOutboundClient {

    private val secureRandom = SecureRandom()

    private val permissiveTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private val sslSocketFactory by lazy {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(permissiveTrustManager), secureRandom)
        sslContext.socketFactory
    }

    /**
     * Tests real end-to-end internet connectivity THROUGH the V2Ray server by opening a real
     * VLESS/Trojan stream to cp.cloudflare.com:80 and verifying an HTTP 204 response.
     * Returns the real end-to-end latency in milliseconds, or Int.MAX_VALUE if the server fails.
     */
    fun verifyRealInternetConnectivity(
        config: V2RayConfig,
        vpnService: VpnService? = null,
        timeoutMs: Int = 3200
    ): Int {
        if (config.protocol != V2RayProtocol.VLESS && config.protocol != V2RayProtocol.TROJAN) {
            return Int.MAX_VALUE
        }
        // Skip unsupported transport types (like kcp/quic) that cannot run over standard TCP/TLS/WS
        val net = config.network.lowercase()
        if (net != "tcp" && net != "ws" && net != "httpupgrade") {
            return Int.MAX_VALUE
        }
        // Skip REALITY configs if publicKey (pbk) is required by server but standard TLS is used
        if (config.tls.equals("reality", ignoreCase = true)) {
            return Int.MAX_VALUE
        }

        return try {
            var validResponse = false
            val elapsed = measureTimeMillis {
                openTunnelStream(
                    config = config,
                    targetHost = "cp.cloudflare.com",
                    targetPort = 80,
                    vpnService = vpnService,
                    connectTimeoutMs = timeoutMs
                ).use { stream ->
                    val httpProbe =
                        "GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
                    stream.output.write(httpProbe.toByteArray(Charsets.US_ASCII))
                    stream.output.flush()

                    val buffer = ByteArray(256)
                    val read = stream.input.read(buffer)
                    if (read > 0) {
                        val responseHead = String(buffer, 0, read, Charsets.US_ASCII)
                        if (responseHead.startsWith("HTTP/1.1 204") ||
                            responseHead.startsWith("HTTP/1.0 204") ||
                            responseHead.startsWith("HTTP/1.1 200")
                        ) {
                            validResponse = true
                        }
                    }
                }
            }
            if (validResponse) elapsed.toInt().coerceAtLeast(1) else Int.MAX_VALUE
        } catch (_: Exception) {
            Int.MAX_VALUE
        }
    }

    /**
     * Opens a real V2Ray outbound tunnel to [targetHost]:[targetPort] through [config].
     */
    fun openTunnelStream(
        config: V2RayConfig,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null,
        connectTimeoutMs: Int = 4500
    ): V2RayTunnelStream {
        val rawSocket = Socket()
        try {
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = connectTimeoutMs
            if (vpnService != null) {
                vpnService.protect(rawSocket)
            }
            rawSocket.connect(InetSocketAddress(config.address, config.port), connectTimeoutMs)

            // 1. Wrap with TLS if security == tls
            val transportSocket: Socket = if (config.tls.equals("tls", ignoreCase = true) || config.port == 443 || config.port == 2053 || config.port == 2083 || config.port == 2087 || config.port == 2096 || config.port == 8443) {
                if (config.tls.equals("none", ignoreCase = true) && config.port != 443) {
                    rawSocket
                } else {
                    val sniHost = config.sni.ifEmpty { config.hostHeader.ifEmpty { config.address } }
                    val sslSocket = sslSocketFactory.createSocket(
                        rawSocket,
                        sniHost,
                        config.port,
                        true
                    ) as SSLSocket

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && sniHost.isNotEmpty() && !isIpLiteral(sniHost)) {
                        runCatching {
                            val params = sslSocket.sslParameters
                            params.serverNames = listOf(SNIHostName(sniHost))
                            sslSocket.sslParameters = params
                        }
                    }
                    sslSocket.soTimeout = connectTimeoutMs
                    sslSocket.startHandshake()
                    sslSocket
                }
            } else {
                rawSocket
            }

            // 2. Wrap with WebSocket if network == ws
            var baseInput: InputStream = transportSocket.getInputStream()
            var baseOutput: OutputStream = BufferedOutputStream(transportSocket.getOutputStream())

            if (config.network.equals("ws", ignoreCase = true) ||
                config.network.equals("httpupgrade", ignoreCase = true)
            ) {
                performWebSocketHandshake(config, baseInput, baseOutput)
                if (config.network.equals("ws", ignoreCase = true)) {
                    baseInput = WebSocketFrameInputStream(baseInput)
                    baseOutput = WebSocketFrameOutputStream(baseOutput, secureRandom)
                }
            }

            // 3. Perform V2Ray Protocol Handshake (VLESS or Trojan)
            return when (config.protocol) {
                V2RayProtocol.VLESS -> {
                    sendVlessHeader(config.uuidOrPassword, targetHost, targetPort, baseOutput)
                    V2RayTunnelStream(
                        underlyingSocket = transportSocket,
                        input = VlessResponseInputStream(baseInput),
                        output = baseOutput
                    )
                }
                V2RayProtocol.TROJAN -> {
                    sendTrojanHeader(config.uuidOrPassword, targetHost, targetPort, baseOutput)
                    V2RayTunnelStream(
                        underlyingSocket = transportSocket,
                        input = baseInput,
                        output = baseOutput
                    )
                }
                else -> throw IllegalArgumentException("Unsupported protocol for direct stream: ${config.protocol}")
            }
        } catch (e: Exception) {
            runCatching { rawSocket.close() }
            throw e
        }
    }

    private fun performWebSocketHandshake(
        config: V2RayConfig,
        input: InputStream,
        output: OutputStream
    ) {
        val wsKeyBytes = ByteArray(16)
        secureRandom.nextBytes(wsKeyBytes)
        val wsKey = Base64.encodeToString(wsKeyBytes, Base64.NO_WRAP)
        val path = config.path.ifEmpty { "/" }.let { if (it.startsWith("/")) it else "/$it" }
        val hostHeader = config.hostHeader.ifEmpty { config.sni.ifEmpty { config.address } }

        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(hostHeader).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("User-Agent: Mozilla/5.0 (Android; Mobile)\r\n\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()

        val headerBuf = ByteArrayOutputStream()
        var matchState = 0
        while (headerBuf.size() < 4096) {
            val b = input.read()
            if (b == -1) throw EOFException("WebSocket handshake closed prematurely")
            headerBuf.write(b)
            matchState = when {
                matchState == 0 && b == '\r'.code -> 1
                matchState == 1 && b == '\n'.code -> 2
                matchState == 2 && b == '\r'.code -> 3
                matchState == 3 && b == '\n'.code -> 4
                b == '\r'.code -> 1
                else -> 0
            }
            if (matchState == 4) break
        }
        val responseStr = headerBuf.toString("US-ASCII")
        if (!responseStr.startsWith("HTTP/1.1 101")) {
            throw IllegalStateException("WebSocket Upgrade failed: ${responseStr.lineSequence().firstOrNull()}")
        }
    }

    private fun sendVlessHeader(
        uuidStr: String,
        targetHost: String,
        targetPort: Int,
        output: OutputStream
    ) {
        val uuidBytes = parseVlessUuidBytes(uuidStr.trim())
        val buf = ByteArrayOutputStream(64)

        // Version (0x00)
        buf.write(0x00)

        // 16-byte UUID
        buf.write(uuidBytes)

        // Addons length (0x00)
        buf.write(0x00)

        // Command (0x01 = TCP)
        buf.write(0x01)

        // Port (2 bytes big-endian)
        buf.write((targetPort ushr 8) and 0xFF)
        buf.write(targetPort and 0xFF)

        // Address Type & Address (VLESS uses 0x01 = IPv4, 0x02 = Domain, 0x03 = IPv6)
        val ipv4Bytes = parseIpv4Literal(targetHost)
        if (ipv4Bytes != null) {
            buf.write(0x01)
            buf.write(ipv4Bytes)
        } else {
            val domainBytes = targetHost.toByteArray(Charsets.UTF_8)
            buf.write(0x02)
            buf.write(domainBytes.size and 0xFF)
            buf.write(domainBytes)
        }

        output.write(buf.toByteArray())
        output.flush()
    }

    private fun parseVlessUuidBytes(raw: String): ByteArray {
        val normalized = if (raw.length == 32 && !raw.contains("-")) {
            "${raw.substring(0, 8)}-${raw.substring(8, 12)}-${raw.substring(12, 16)}-${raw.substring(16, 20)}-${raw.substring(20, 32)}"
        } else {
            raw
        }
        return try {
            val uuid = UUID.fromString(normalized)
            val out = ByteArray(16)
            val msb = uuid.mostSignificantBits
            val lsb = uuid.leastSignificantBits
            for (i in 0..7) out[i] = ((msb ushr (8 * (7 - i))) and 0xFF).toByte()
            for (i in 0..7) out[8 + i] = ((lsb ushr (8 * (7 - i))) and 0xFF).toByte()
            out
        } catch (_: Exception) {
            // Xray-core UUIDv5 mapping for custom non-UUID strings
            val sha1 = MessageDigest.getInstance("SHA-1")
            sha1.update(ByteArray(16)) // Nil namespace
            val hash = sha1.digest(raw.toByteArray(Charsets.UTF_8))
            val out = hash.copyOfRange(0, 16)
            out[6] = ((out[6].toInt() and 0x0F) or 0x50).toByte()
            out[8] = ((out[8].toInt() and 0x3F) or 0x80).toByte()
            out
        }
    }

    private fun sendTrojanHeader(
        password: String,
        targetHost: String,
        targetPort: Int,
        output: OutputStream
    ) {
        val sha224 = MessageDigest.getInstance("SHA-224")
        val digest = sha224.digest(password.toByteArray(Charsets.UTF_8))
        val hexPassword = digest.joinToString("") { "%02x".format(it) }

        val buf = ByteArrayOutputStream(128)
        buf.write(hexPassword.toByteArray(Charsets.US_ASCII))
        buf.write('\r'.code)
        buf.write('\n'.code)

        // Command 0x01 (CONNECT)
        buf.write(0x01)

        // SOCKS5 Address Type (0x01 = IPv4, 0x03 = Domain)
        val ipv4Bytes = parseIpv4Literal(targetHost)
        if (ipv4Bytes != null) {
            buf.write(0x01)
            buf.write(ipv4Bytes)
        } else {
            val domainBytes = targetHost.toByteArray(Charsets.UTF_8)
            buf.write(0x03)
            buf.write(domainBytes.size and 0xFF)
            buf.write(domainBytes)
        }

        // Port (2 bytes big-endian)
        buf.write((targetPort ushr 8) and 0xFF)
        buf.write(targetPort and 0xFF)

        buf.write('\r'.code)
        buf.write('\n'.code)

        output.write(buf.toByteArray())
        output.flush()
    }

    private fun isIpLiteral(host: String): Boolean {
        return parseIpv4Literal(host) != null || host.contains(":")
    }

    private fun parseIpv4Literal(host: String): ByteArray? {
        val parts = host.split(".")
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for (i in 0..3) {
            val num = parts[i].toIntOrNull() ?: return null
            if (num !in 0..255) return null
            bytes[i] = num.toByte()
        }
        return bytes
    }
}

/**
 * Strips the 2-byte VLESS response header ([version, addonLength] + addonBytes) on the first read.
 */
private class VlessResponseInputStream(
    private val delegate: InputStream
) : InputStream() {
    private var headerConsumed = false

    private fun ensureHeaderRead() {
        if (headerConsumed) return
        val version = delegate.read()
        if (version == -1) throw EOFException("VLESS response closed before header")
        val addonLen = delegate.read()
        if (addonLen == -1) throw EOFException("VLESS response closed at addon length")
        var remaining = addonLen
        while (remaining > 0) {
            val skipped = delegate.skip(remaining.toLong()).toInt()
            if (skipped <= 0) {
                if (delegate.read() == -1) throw EOFException("VLESS addon EOF")
                remaining--
            } else {
                remaining -= skipped
            }
        }
        headerConsumed = true
    }

    override fun read(): Int {
        ensureHeaderRead()
        return delegate.read()
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        ensureHeaderRead()
        return delegate.read(b, off, len)
    }

    override fun close() {
        delegate.close()
    }
}

/**
 * RFC 6455 Client-to-Server Masked Binary WebSocket Frame OutputStream.
 */
private class WebSocketFrameOutputStream(
    private val rawOut: OutputStream,
    private val random: SecureRandom
) : OutputStream() {

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        val maskKey = ByteArray(4)
        random.nextBytes(maskKey)

        // FIN (0x80) + Binary Opcode (0x02)
        rawOut.write(0x82)

        // Mask bit set (0x80) + payload length
        when {
            len <= 125 -> {
                rawOut.write(0x80 or len)
            }
            len <= 65535 -> {
                rawOut.write(0x80 or 126)
                rawOut.write((len ushr 8) and 0xFF)
                rawOut.write(len and 0xFF)
            }
            else -> {
                rawOut.write(0x80 or 127)
                val longLen = len.toLong()
                for (i in 7 downTo 0) {
                    rawOut.write(((longLen ushr (8 * i)) and 0xFF).toInt())
                }
            }
        }

        rawOut.write(maskKey)

        val maskedPayload = ByteArray(len)
        for (i in 0 until len) {
            maskedPayload[i] = (b[off + i].toInt() xor maskKey[i and 3].toInt()).toByte()
        }
        rawOut.write(maskedPayload)
    }

    override fun flush() {
        rawOut.flush()
    }

    override fun close() {
        rawOut.close()
    }
}

/**
 * RFC 6455 Server-to-Client WebSocket Frame InputStream.
 */
private class WebSocketFrameInputStream(
    private val rawIn: InputStream
) : InputStream() {
    private var currentFrameRemaining = 0
    private var currentFrameMask: ByteArray? = null
    private var currentMaskIndex = 0
    private var eofReached = false

    private fun readNextFrameHeader(): Boolean {
        while (currentFrameRemaining == 0 && !eofReached) {
            val b0 = rawIn.read()
            if (b0 == -1) {
                eofReached = true
                return false
            }
            val opcode = b0 and 0x0F
            if (opcode == 0x08) { // Close frame
                eofReached = true
                return false
            }

            val b1 = rawIn.read()
            if (b1 == -1) {
                eofReached = true
                return false
            }
            val isMasked = (b1 and 0x80) != 0
            var payloadLen = b1 and 0x7F

            if (payloadLen == 126) {
                val hi = rawIn.read()
                val lo = rawIn.read()
                if (hi == -1 || lo == -1) {
                    eofReached = true
                    return false
                }
                payloadLen = (hi shl 8) or lo
            } else if (payloadLen == 127) {
                var longLen = 0L
                for (i in 0 until 8) {
                    val v = rawIn.read()
                    if (v == -1) {
                        eofReached = true
                        return false
                    }
                    longLen = (longLen shl 8) or v.toLong()
                }
                payloadLen = longLen.toInt()
            }

            currentFrameMask = if (isMasked) {
                val m = ByteArray(4)
                readFully(m)
                m
            } else {
                null
            }
            currentMaskIndex = 0

            // Ignore Ping/Pong control frames (0x09, 0x0A) by skipping their payload
            if (opcode == 0x09 || opcode == 0x0A) {
                val skipBuf = ByteArray(payloadLen)
                readFully(skipBuf)
                continue
            }

            currentFrameRemaining = payloadLen
        }
        return currentFrameRemaining > 0
    }

    private fun readFully(buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val r = rawIn.read(buf, offset, buf.size - offset)
            if (r == -1) throw EOFException("Unexpected EOF in WebSocket frame")
            offset += r
        }
    }

    override fun read(): Int {
        if (!readNextFrameHeader()) return -1
        val b = rawIn.read()
        if (b == -1) {
            eofReached = true
            return -1
        }
        currentFrameRemaining--
        val mask = currentFrameMask
        return if (mask != null) {
            val unmasked = (b xor (mask[currentMaskIndex and 3].toInt() and 0xFF)) and 0xFF
            currentMaskIndex++
            unmasked
        } else {
            b
        }
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!readNextFrameHeader()) return -1
        val toRead = minOf(len, currentFrameRemaining)
        val r = rawIn.read(b, off, toRead)
        if (r == -1) {
            eofReached = true
            return -1
        }
        currentFrameRemaining -= r
        val mask = currentFrameMask
        if (mask != null) {
            for (i in 0 until r) {
                b[off + i] = (b[off + i].toInt() xor mask[currentMaskIndex and 3].toInt()).toByte()
                currentMaskIndex++
            }
        }
        return r
    }

    override fun close() {
        rawIn.close()
    }
}
