package com.meh.vpn.vpn

import android.net.VpnService
import android.os.Build
import android.util.Base64
import com.meh.vpn.model.V2RayConfig
import com.meh.vpn.model.V2RayProtocol
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
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.system.measureTimeMillis

/**
 * Represents an established, bi-directional V2Ray tunnel stream (VLESS or Trojan)
 * connected to a remote target [targetHost]:[targetPort].
 */
class V2RayTunnelStream(
    internal val underlyingSocket: Socket,
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

    private const val DATA_PLANE_IDLE_TIMEOUT_MS = 120_000
    private const val BLACKLIST_TTL_MS = 180_000L

    private val secureRandom = SecureRandom()
    private val deadNodeBlacklist = ConcurrentHashMap<String, Long>()
    private val consecutiveServerFailures = java.util.concurrent.atomic.AtomicInteger(0)

    @Volatile
    var onTunnelDegradedListener: (() -> Unit)? = null

    fun nodeKey(config: V2RayConfig): String =
        "${config.protocol}:${config.address.lowercase()}:${config.port}"

    fun isNodeBlacklisted(config: V2RayConfig): Boolean {
        val key = nodeKey(config)
        val expiresAt = deadNodeBlacklist[key] ?: return false
        if (System.currentTimeMillis() > expiresAt) {
            deadNodeBlacklist.remove(key)
            return false
        }
        return true
    }

    fun markNodeDead(config: V2RayConfig) {
        deadNodeBlacklist[nodeKey(config)] = System.currentTimeMillis() + BLACKLIST_TTL_MS
        consecutiveServerFailures.set(0)
    }

    fun clearBlacklist() {
        deadNodeBlacklist.clear()
        consecutiveServerFailures.set(0)
    }

    private fun recordTunnelSuccess() {
        consecutiveServerFailures.set(0)
    }

    private fun recordTunnelServerFailure() {
        val count = consecutiveServerFailures.incrementAndGet()
        if (count >= 3) {
            consecutiveServerFailures.set(0)
            onTunnelDegradedListener?.invoke()
        }
    }

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
     * VLESS/Trojan stream to port 443 and verifying a genuine TLS ServerHello response.
     */
    fun verifyRealInternetConnectivity(
        config: V2RayConfig,
        vpnService: VpnService? = null,
        timeoutMs: Int = 3200
    ): Int {
        if (config.protocol != V2RayProtocol.VLESS && config.protocol != V2RayProtocol.TROJAN) {
            return Int.MAX_VALUE
        }
        val net = config.network.lowercase()
        if (net != "tcp" && net != "ws" && net != "httpupgrade") {
            return Int.MAX_VALUE
        }
        if (config.tls.equals("reality", ignoreCase = true)) {
            return Int.MAX_VALUE
        }

        val tlsProbeHosts = listOf("www.youtube.com", "www.instagram.com")

        for (probeHost in tlsProbeHosts) {
            try {
                var validTlsServerHello = false
                val elapsed = measureTimeMillis {
                    openTunnelStream(
                        config = config,
                        targetHost = probeHost,
                        targetPort = 443,
                        vpnService = vpnService,
                        connectTimeoutMs = timeoutMs,
                        isHealthProbe = true
                    ).use { stream ->
                        val clientHello = buildTlsClientHelloProbe(probeHost)
                        stream.output.write(clientHello)
                        stream.output.flush()

                        val buffer = ByteArray(128)
                        var totalRead = 0
                        while (totalRead < 6) {
                            val r = stream.input.read(buffer, totalRead, buffer.size - totalRead)
                            if (r <= 0) break
                            totalRead += r
                        }
                        // Verify genuine TLS Handshake (0x16), TLS 1.x (0x03), ServerHello (0x02)
                        if (totalRead >= 6 &&
                            (buffer[0].toInt() and 0xFF) == 0x16 &&
                            (buffer[1].toInt() and 0xFF) == 0x03 &&
                            (buffer[5].toInt() and 0xFF) == 0x02
                        ) {
                            validTlsServerHello = true
                        }
                    }
                }
                if (validTlsServerHello) {
                    return elapsed.toInt().coerceAtLeast(1)
                }
            } catch (_: Exception) {
            }
        }
        return Int.MAX_VALUE
    }

    internal fun buildTlsClientHelloProbe(sniHost: String): ByteArray {
        val sniBytes = sniHost.toByteArray(Charsets.US_ASCII)
        val extOut = ByteArrayOutputStream(64)

        // Extension: server_name (0x0000)
        val sniExtLen = sniBytes.size + 5
        val sniListLen = sniBytes.size + 3
        extOut.write(0x00)
        extOut.write(0x00)
        extOut.write((sniExtLen ushr 8) and 0xFF)
        extOut.write(sniExtLen and 0xFF)
        extOut.write((sniListLen ushr 8) and 0xFF)
        extOut.write(sniListLen and 0xFF)
        extOut.write(0x00)
        extOut.write((sniBytes.size ushr 8) and 0xFF)
        extOut.write(sniBytes.size and 0xFF)
        extOut.write(sniBytes)

        // Extension: supported_groups (0x000a) -> x25519 (0x001d), secp256r1 (0x0017)
        extOut.write(byteArrayOf(0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17))
        // Extension: ec_point_formats (0x000b)
        extOut.write(byteArrayOf(0x00, 0x0b, 0x00, 0x02, 0x01, 0x00))
        // Extension: signature_algorithms (0x000d)
        extOut.write(byteArrayOf(0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x04, 0x03))

        val extBytes = extOut.toByteArray()
        val bodyOut = ByteArrayOutputStream(128)
        // Client Version TLS 1.2 (0x0303)
        bodyOut.write(0x03)
        bodyOut.write(0x03)
        // Client Random (32 bytes)
        val randomBytes = ByteArray(32)
        secureRandom.nextBytes(randomBytes)
        bodyOut.write(randomBytes)
        // Session ID (0)
        bodyOut.write(0x00)
        // Cipher Suites (8 bytes)
        bodyOut.write(
            byteArrayOf(
                0x00, 0x08,
                0x13, 0x01,
                0x13, 0x02,
                0xC0.toByte(), 0x2F,
                0xC0.toByte(), 0x2B
            )
        )
        // Compression Methods (null)
        bodyOut.write(byteArrayOf(0x01, 0x00))
        // Extensions
        bodyOut.write((extBytes.size ushr 8) and 0xFF)
        bodyOut.write(extBytes.size and 0xFF)
        bodyOut.write(extBytes)

        val bodyBytes = bodyOut.toByteArray()
        val hsLen = bodyBytes.size
        val recLen = hsLen + 4

        val out = ByteArrayOutputStream(recLen + 5)
        out.write(0x16)
        out.write(0x03)
        out.write(0x01)
        out.write((recLen ushr 8) and 0xFF)
        out.write(recLen and 0xFF)
        out.write(0x01)
        out.write((hsLen ushr 16) and 0xFF)
        out.write((hsLen ushr 8) and 0xFF)
        out.write(hsLen and 0xFF)
        out.write(bodyBytes)
        return out.toByteArray()
    }

    /**
     * Opens a real outbound V2Ray (VLESS / Trojan) tunnel stream to [targetHost]:[targetPort].
     */
    fun openTunnelStream(
        config: V2RayConfig,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null,
        connectTimeoutMs: Int = 4500,
        isHealthProbe: Boolean = false
    ): V2RayTunnelStream {
        val rawSocket = Socket()
        try {
            rawSocket.tcpNoDelay = true
            rawSocket.keepAlive = true
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

            // Switch from short connectTimeoutMs (4.5s) to long data-plane idle timeout (120s)
            val activeReadTimeout = if (isHealthProbe || targetPort == 53) connectTimeoutMs else DATA_PLANE_IDLE_TIMEOUT_MS
            runCatching {
                rawSocket.soTimeout = activeReadTimeout
                transportSocket.soTimeout = activeReadTimeout
            }

            // 3. Perform V2Ray Protocol Handshake (VLESS or Trojan) coalesced with first payload write
            val tunnelStream = when (config.protocol) {
                V2RayProtocol.VLESS -> {
                    val headerBytes = buildVlessHeaderBytes(config.uuidOrPassword, targetHost, targetPort)
                    V2RayTunnelStream(
                        underlyingSocket = transportSocket,
                        input = VlessResponseInputStream(baseInput),
                        output = PrependingHeaderOutputStream(headerBytes, baseOutput)
                    )
                }
                V2RayProtocol.TROJAN -> {
                    val headerBytes = buildTrojanHeaderBytes(config.uuidOrPassword, targetHost, targetPort)
                    V2RayTunnelStream(
                        underlyingSocket = transportSocket,
                        input = baseInput,
                        output = PrependingHeaderOutputStream(headerBytes, baseOutput)
                    )
                }
                else -> throw IllegalArgumentException("Unsupported protocol: ${config.protocol}")
            }
            if (!isHealthProbe) {
                recordTunnelSuccess()
            }
            return tunnelStream
        } catch (e: Exception) {
            runCatching { rawSocket.close() }
            if (!isHealthProbe) {
                recordTunnelServerFailure()
            }
            throw e
        }
    }

    /**
     * Filters out Iranian ISP censorship sinkhole IPs (10.10.34.34-36) and invalid/loopback answers.
     */
    internal fun isPoisonedOrPrivateIp(ip: String): Boolean {
        return ip.startsWith("10.") ||
            ip.startsWith("127.") ||
            ip.startsWith("0.") ||
            ip.startsWith("192.168.") ||
            ip == "255.255.255.255"
    }

    private fun performWebSocketHandshake(
        config: V2RayConfig,
        input: InputStream,
        output: OutputStream
    ) {
        val wsKeyBytes = ByteArray(16)
        secureRandom.nextBytes(wsKeyBytes)
        val wsKey = Base64.encodeToString(wsKeyBytes, Base64.NO_WRAP)
        val path = sanitizeWebSocketPath(config.path)
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

    private fun sanitizeWebSocketPath(rawPath: String): String {
        val base = rawPath.ifEmpty { "/" }.let { if (it.startsWith("/")) it else "/$it" }
        if (!base.contains("ed=")) return base
        val pathPart = base.substringBefore("?")
        val queryPart = base.substringAfter("?", "")
        if (queryPart.isEmpty()) return pathPart.ifEmpty { "/" }
        val filteredParams = queryPart.split("&")
            .filter { !it.startsWith("ed=", ignoreCase = true) && it.isNotEmpty() }
        return if (filteredParams.isEmpty()) {
            pathPart.ifEmpty { "/" }
        } else {
            "${pathPart.ifEmpty { "/" }}?${filteredParams.joinToString("&")}"
        }
    }

    private fun buildVlessHeaderBytes(
        uuidStr: String,
        targetHost: String,
        targetPort: Int
    ): ByteArray {
        val uuidBytes = parseVlessUuidBytes(uuidStr.trim())
        val buf = ByteArrayOutputStream(64)

        buf.write(0x00)
        buf.write(uuidBytes)
        buf.write(0x00)
        buf.write(0x01)

        buf.write((targetPort ushr 8) and 0xFF)
        buf.write(targetPort and 0xFF)

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

        return buf.toByteArray()
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
            val sha1 = MessageDigest.getInstance("SHA-1")
            sha1.update(ByteArray(16))
            val hash = sha1.digest(raw.toByteArray(Charsets.UTF_8))
            val out = hash.copyOfRange(0, 16)
            out[6] = ((out[6].toInt() and 0x0F) or 0x50).toByte()
            out[8] = ((out[8].toInt() and 0x3F) or 0x80).toByte()
            out
        }
    }

    private fun buildTrojanHeaderBytes(
        password: String,
        targetHost: String,
        targetPort: Int
    ): ByteArray {
        val sha224 = MessageDigest.getInstance("SHA-224")
        val digest = sha224.digest(password.toByteArray(Charsets.UTF_8))
        val hexPassword = digest.joinToString("") { "%02x".format(it) }

        val buf = ByteArrayOutputStream(128)
        buf.write(hexPassword.toByteArray(Charsets.US_ASCII))
        buf.write('\r'.code)
        buf.write('\n'.code)

        buf.write(0x01)

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

        buf.write((targetPort ushr 8) and 0xFF)
        buf.write(targetPort and 0xFF)

        buf.write('\r'.code)
        buf.write('\n'.code)

        return buf.toByteArray()
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

private class PrependingHeaderOutputStream(
    private val headerBytes: ByteArray,
    private val delegate: OutputStream
) : OutputStream() {
    private var headerSent = false

    @Synchronized
    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        if (!headerSent) {
            headerSent = true
            val combined = ByteArray(headerBytes.size + len)
            System.arraycopy(headerBytes, 0, combined, 0, headerBytes.size)
            System.arraycopy(b, off, combined, headerBytes.size, len)
            delegate.write(combined, 0, combined.size)
        } else {
            delegate.write(b, off, len)
        }
    }

    @Synchronized
    override fun flush() {
        if (!headerSent) {
            headerSent = true
            delegate.write(headerBytes, 0, headerBytes.size)
        }
        delegate.flush()
    }

    override fun close() {
        delegate.close()
    }
}

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

private class WebSocketFrameOutputStream(
    private val rawOut: OutputStream,
    private val random: SecureRandom
) : OutputStream() {

    @Synchronized
    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        val maskKey = ByteArray(4)
        random.nextBytes(maskKey)

        rawOut.write(0x82)

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

    @Synchronized
    override fun flush() {
        rawOut.flush()
    }

    override fun close() {
        rawOut.close()
    }
}

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
            if (opcode == 0x08) {
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
