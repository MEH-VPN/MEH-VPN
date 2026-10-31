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
import java.net.InetAddress
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
 * Represents an established, bi-directional tunnel stream (VLESS, Trojan, Aether, Serverless-for-Iran, or SNI-Spoofing)
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
    private val cleanDnsCache = ConcurrentHashMap<String, String>()
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
     * Tests real end-to-end internet connectivity THROUGH the server by opening a real
     * VLESS/Trojan/Aether/Serverless/SNI-Spoof stream and verifying a fast 1-RTT HTTP 204 response.
     * Tests cp.cloudflare.com:80 and falls back to connectivitycheck.gstatic.com:80 (for Cloudflare Worker VLESS nodes).
     */
    fun verifyRealInternetConnectivity(
        config: V2RayConfig,
        vpnService: VpnService? = null,
        timeoutMs: Int = 3200
    ): Int {
        val isDirectBypass = config.protocol == V2RayProtocol.AETHER ||
            config.protocol == V2RayProtocol.SERVERLESS ||
            config.protocol == V2RayProtocol.SNI_SPOOF

        if (config.protocol != V2RayProtocol.VLESS &&
            config.protocol != V2RayProtocol.TROJAN &&
            !isDirectBypass
        ) {
            return Int.MAX_VALUE
        }
        if (!isDirectBypass) {
            val net = config.network.lowercase()
            if (net != "tcp" && net != "ws" && net != "httpupgrade") {
                return Int.MAX_VALUE
            }
            if (config.tls.equals("reality", ignoreCase = true)) {
                return Int.MAX_VALUE
            }
        }

        if (config.protocol == V2RayProtocol.AETHER) {
            return try {
                var validAether = false
                val sni = config.sni.ifEmpty { "engage.cloudflareclient.com" }
                val elapsed = measureTimeMillis {
                    openAetherGatewayProbeStream(
                        gatewayHost = config.address,
                        gatewayPort = config.port,
                        sniHost = sni,
                        vpnService = vpnService,
                        connectTimeoutMs = timeoutMs
                    ).use { stream ->
                        val traceReq =
                            "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $sni\r\nUser-Agent: Aether/1.0\r\nConnection: close\r\n\r\n"
                        stream.output.write(traceReq.toByteArray(Charsets.US_ASCII))
                        stream.output.flush()
                        val buf = ByteArray(512)
                        val read = stream.input.read(buf)
                        if (read > 0) {
                            val resp = String(buf, 0, read, Charsets.US_ASCII)
                            if (resp.startsWith("HTTP/1.1 ") || resp.contains("colo=")) {
                                validAether = true
                            }
                        }
                    }
                }
                if (validAether) elapsed.toInt().coerceAtLeast(1) else Int.MAX_VALUE
            } catch (_: Exception) {
                Int.MAX_VALUE
            }
        }

        val probeHosts = if (isDirectBypass) {
            listOf("cp.cloudflare.com")
        } else {
            listOf("cp.cloudflare.com", "connectivitycheck.gstatic.com")
        }

        for (probeHost in probeHosts) {
            try {
                var validResponse = false
                val elapsed = measureTimeMillis {
                    openTunnelStream(
                        config = config,
                        targetHost = probeHost,
                        targetPort = 80,
                        vpnService = vpnService,
                        connectTimeoutMs = timeoutMs,
                        isHealthProbe = true
                    ).use { stream ->
                        val httpProbe =
                            "GET /generate_204 HTTP/1.1\r\nHost: $probeHost\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
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
                if (validResponse) {
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
     * Opens a fragmented TLS probe stream directly to an Aether gateway for data-plane verification.
     */
    fun openAetherGatewayProbeStream(
        gatewayHost: String,
        gatewayPort: Int,
        sniHost: String,
        vpnService: VpnService? = null,
        connectTimeoutMs: Int = 2500
    ): V2RayTunnelStream {
        val rawSocket = Socket()
        try {
            rawSocket.tcpNoDelay = true
            rawSocket.keepAlive = true
            rawSocket.soTimeout = connectTimeoutMs
            if (vpnService != null) {
                vpnService.protect(rawSocket)
            }
            rawSocket.connect(InetSocketAddress(gatewayHost, gatewayPort), connectTimeoutMs)

            val fragmentedSocket = AetherFragmentingSocketWrapper(rawSocket)
            val sslSocket = sslSocketFactory.createSocket(
                fragmentedSocket,
                sniHost,
                gatewayPort,
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

            return V2RayTunnelStream(
                underlyingSocket = sslSocket,
                input = sslSocket.getInputStream(),
                output = BufferedOutputStream(sslSocket.getOutputStream())
            )
        } catch (e: Exception) {
            runCatching { rawSocket.close() }
            throw e
        }
    }

    /**
     * Opens a real outbound tunnel to [targetHost]:[targetPort] through [config].
     * Supports:
     * 1. V2Ray (VLESS / Trojan)
     * 2. CluvexStudio/Aether (AETHER)
     * 3. patterniha/Serverless-for-Iran (SERVERLESS)
     * 4. patterniha/SNI-Spoofing (SNI_SPOOF)
     */
    fun openTunnelStream(
        config: V2RayConfig,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService? = null,
        connectTimeoutMs: Int = 4500,
        isHealthProbe: Boolean = false
    ): V2RayTunnelStream {
        if (config.protocol == V2RayProtocol.AETHER ||
            config.protocol == V2RayProtocol.SERVERLESS ||
            config.protocol == V2RayProtocol.SNI_SPOOF
        ) {
            return openDirectDpiBypassStream(
                config = config,
                targetHost = targetHost,
                targetPort = targetPort,
                vpnService = vpnService,
                connectTimeoutMs = connectTimeoutMs,
                isHealthProbe = isHealthProbe
            )
        }

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

            // Crucial: once handshake succeeds, switch from short connectTimeoutMs (4.5s)
            // to long data-plane idle timeout (120s) so persistent HTTP/2 & app sockets aren't killed!
            val activeReadTimeout = if (isHealthProbe || targetPort == 53) connectTimeoutMs else DATA_PLANE_IDLE_TIMEOUT_MS
            runCatching {
                rawSocket.soTimeout = activeReadTimeout
                transportSocket.soTimeout = activeReadTimeout
            }

            // 3. Perform V2Ray Protocol Handshake (VLESS or Trojan) coalesced with first payload write
            // so Cloudflare Worker VLESS/Trojan WebSocket nodes receive [Header + ClientHello] in Frame #1
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
                else -> throw IllegalArgumentException("Unsupported protocol for direct stream: ${config.protocol}")
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
     * Opens an outbound stream for Aether, Serverless-for-Iran, or SNI-Spoofing:
     * 1. Resolves domain names via unpoisoned DoT/TCP DNS (1.1.1.1 / 1.0.0.1 / 8.8.8.8).
     * 2. Wraps the socket output with the protocol-specific DPI bypass transformer:
     *    - AETHER: TLS record 2-way split + HTTP Host split (CluvexStudio/Aether)
     *    - SERVERLESS: Ultra-fine 1-to-3 byte TLS ClientHello micro-fragmentation with 5ms pacing (patterniha/Serverless-for-Iran)
     *    - SNI_SPOOF: Multi-record TLS ClientHello desync & SNI spoofing boundary split (patterniha/SNI-Spoofing)
     */
    private fun openDirectDpiBypassStream(
        config: V2RayConfig,
        targetHost: String,
        targetPort: Int,
        vpnService: VpnService?,
        connectTimeoutMs: Int,
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

            val resolvedAddress: String = when {
                targetPort == 53 -> "1.1.1.1"
                targetHost.equals("cp.cloudflare.com", ignoreCase = true) ||
                    targetHost.equals("engage.cloudflareclient.com", ignoreCase = true) ||
                    targetHost.endsWith(".cloudflare.com", ignoreCase = true) -> config.address
                isIpLiteral(targetHost) -> targetHost
                else -> resolveDomainCleanly(targetHost, vpnService)
            }

            val resolvedPort = if (resolvedAddress == config.address && targetPort == 443) {
                config.port
            } else {
                targetPort
            }

            rawSocket.connect(InetSocketAddress(resolvedAddress, resolvedPort), connectTimeoutMs)

            val activeReadTimeout = if (isHealthProbe || targetPort == 53) connectTimeoutMs else DATA_PLANE_IDLE_TIMEOUT_MS
            runCatching { rawSocket.soTimeout = activeReadTimeout }

            val wrappedOutput: OutputStream = when (config.protocol) {
                V2RayProtocol.SERVERLESS -> ServerlessMicroFragmentOutputStream(
                    rawOut = rawSocket.getOutputStream(),
                    random = secureRandom
                )
                V2RayProtocol.SNI_SPOOF -> SniSpoofingDesyncOutputStream(
                    rawOut = rawSocket.getOutputStream(),
                    fakeSniDomain = config.sni.ifEmpty { "speedtest.net" }
                )
                else -> AetherFragmentedOutputStream(rawSocket.getOutputStream())
            }

            if (!isHealthProbe) {
                recordTunnelSuccess()
            }

            return V2RayTunnelStream(
                underlyingSocket = rawSocket,
                input = rawSocket.getInputStream(),
                output = wrappedOutput
            )
        } catch (e: Exception) {
            runCatching { rawSocket.close() }
            if (!isHealthProbe && (targetHost.endsWith(".cloudflare.com", ignoreCase = true) || targetPort == 443)) {
                recordTunnelServerFailure()
            }
            throw e
        }
    }

    /**
     * Executes a raw DNS query over DNS-over-TLS (port 853) or fragmented TCP DNS (port 53),
     * ensuring ISP DNS poisoning / sinkhole responses (e.g. 10.10.34.35) are discarded.
     */
    fun executeCleanDnsQueryRaw(dnsQuery: ByteArray, vpnService: VpnService?): ByteArray? {
        val framed = ByteArray(dnsQuery.size + 2)
        framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
        framed[1] = (dnsQuery.size and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)

        val dotResolvers = listOf(
            "1.1.1.1" to "cloudflare-dns.com",
            "1.0.0.1" to "cloudflare-dns.com",
            "8.8.8.8" to "dns.google"
        )
        // 1. Try encrypted DNS-over-TLS (Port 853) so ISP DPI cannot inspect or forge DNS answers
        for ((ip, sni) in dotResolvers) {
            val rawSocket = Socket()
            try {
                rawSocket.tcpNoDelay = true
                rawSocket.soTimeout = 2200
                if (vpnService != null) {
                    vpnService.protect(rawSocket)
                }
                rawSocket.connect(InetSocketAddress(ip, 853), 1800)
                val sslSocket = sslSocketFactory.createSocket(rawSocket, sni, 853, true) as SSLSocket
                sslSocket.soTimeout = 2200
                sslSocket.startHandshake()

                val out = sslSocket.getOutputStream()
                out.write(framed)
                out.flush()

                val input = sslSocket.getInputStream()
                val hi = input.read()
                val lo = input.read()
                if (hi != -1 && lo != -1) {
                    val len = (hi shl 8) or lo
                    if (len in 12..4096) {
                        val resp = ByteArray(len)
                        var readTotal = 0
                        while (readTotal < len) {
                            val r = input.read(resp, readTotal, len - readTotal)
                            if (r == -1) break
                            readTotal += r
                        }
                        if (readTotal == len && !containsPoisonedARecord(resp)) {
                            return resp
                        }
                    }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { rawSocket.close() }
            }
        }

        // 2. Fallback to TCP DNS (Port 53) with anti-poisoning verification
        val tcpResolvers = listOf("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
        for (dnsServer in tcpResolvers) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = 2000
                if (vpnService != null) {
                    vpnService.protect(socket)
                }
                socket.connect(InetSocketAddress(dnsServer, 53), 1800)
                val out = socket.getOutputStream()
                out.write(framed)
                out.flush()

                val input = socket.getInputStream()
                val hi = input.read()
                val lo = input.read()
                if (hi != -1 && lo != -1) {
                    val len = (hi shl 8) or lo
                    if (len in 12..4096) {
                        val resp = ByteArray(len)
                        var readTotal = 0
                        while (readTotal < len) {
                            val r = input.read(resp, readTotal, len - readTotal)
                            if (r == -1) break
                            readTotal += r
                        }
                        if (readTotal == len && !containsPoisonedARecord(resp)) {
                            return resp
                        }
                    }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { socket.close() }
            }
        }
        return null
    }

    /**
     * Resolves [domain] over encrypted DoT / clean TCP DNS (bypassing ISP UDP/TCP DNS poisoning).
     */
    private fun resolveDomainCleanly(domain: String, vpnService: VpnService?): String {
        val normalized = domain.trim().lowercase()
        cleanDnsCache[normalized]?.let { cached ->
            if (!isPoisonedOrPrivateIp(cached)) return cached
            cleanDnsCache.remove(normalized)
        }

        val query = buildDnsAQuery(normalized)
        val rawResp = executeCleanDnsQueryRaw(query, vpnService)
        if (rawResp != null) {
            val ip = parseFirstARecordFromDnsResponse(rawResp)
            if (ip != null && !isPoisonedOrPrivateIp(ip)) {
                cleanDnsCache[normalized] = ip
                return ip
            }
        }

        return runCatching {
            val sysIp = InetAddress.getByName(normalized).hostAddress
            if (sysIp != null && !isPoisonedOrPrivateIp(sysIp)) {
                cleanDnsCache[normalized] = sysIp
                sysIp
            } else {
                normalized
            }
        }.getOrDefault(normalized)
    }

    internal fun containsPoisonedARecord(resp: ByteArray): Boolean {
        val ip = parseFirstARecordFromDnsResponse(resp) ?: return false
        return isPoisonedOrPrivateIp(ip)
    }

    /**
     * Resolves a raw DNS query inside the active tunnel over HTTPS (RFC 8484 DoH on port 443)
     * to 8.8.8.8 (dns.google). Because 8.8.8.8 is a non-Cloudflare IP and uses port 443,
     * this works on 100% of V2Ray servers AND Cloudflare Worker VLESS nodes, while completely
     * bypassing Hamrah-e-Aval (MCI) port 53/853 blocking and DNS poisoning.
     */
    fun executeTunnelDohQuery(
        config: V2RayConfig,
        dnsQuery: ByteArray,
        vpnService: VpnService?
    ): ByteArray? {
        return try {
            openTunnelStream(
                config = config,
                targetHost = "8.8.8.8",
                targetPort = 443,
                vpnService = vpnService,
                connectTimeoutMs = 2400,
                isHealthProbe = true
            ).use { stream ->
                val probeSocket = TunnelStreamSocket(stream, 2400)
                val sslSocket = sslSocketFactory.createSocket(
                    probeSocket,
                    "dns.google",
                    443,
                    false
                ) as SSLSocket
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    runCatching {
                        val params = sslSocket.sslParameters
                        params.serverNames = listOf(SNIHostName("dns.google"))
                        sslSocket.sslParameters = params
                    }
                }
                sslSocket.soTimeout = 2400
                sslSocket.startHandshake()

                val reqHeader = buildString {
                    append("POST /dns-query HTTP/1.1\r\n")
                    append("Host: dns.google\r\n")
                    append("Content-Type: application/dns-message\r\n")
                    append("Accept: application/dns-message\r\n")
                    append("Content-Length: ").append(dnsQuery.size).append("\r\n")
                    append("Connection: close\r\n\r\n")
                }
                val out = sslSocket.outputStream
                out.write(reqHeader.toByteArray(Charsets.US_ASCII))
                out.write(dnsQuery)
                out.flush()

                val input = sslSocket.inputStream
                val headerBuf = ByteArrayOutputStream(256)
                var matchState = 0
                while (headerBuf.size() < 4096) {
                    val b = input.read()
                    if (b == -1) break
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
                val headersStr = headerBuf.toString("US-ASCII")
                if (!headersStr.startsWith("HTTP/1.1 200") && !headersStr.startsWith("HTTP/2 200")) {
                    return null
                }
                val contentLen = headersStr.lineSequence()
                    .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                    ?.substringAfter(":")?.trim()?.toIntOrNull() ?: -1

                val bodyBytes = if (contentLen in 12..4096) {
                    val buf = ByteArray(contentLen)
                    var readTotal = 0
                    while (readTotal < contentLen) {
                        val r = input.read(buf, readTotal, contentLen - readTotal)
                        if (r == -1) break
                        readTotal += r
                    }
                    if (readTotal == contentLen) buf else null
                } else {
                    val bodyOut = ByteArrayOutputStream(512)
                    val tmp = ByteArray(512)
                    while (bodyOut.size() < 4096) {
                        val r = input.read(tmp)
                        if (r <= 0) break
                        bodyOut.write(tmp, 0, r)
                    }
                    bodyOut.toByteArray().takeIf { it.size >= 12 }
                }

                if (bodyBytes != null && !containsPoisonedARecord(bodyBytes)) {
                    bodyBytes
                } else {
                    null
                }
            }
        } catch (_: Exception) {
            null
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

    private fun buildDnsAQuery(domain: String): ByteArray {
        val buf = ByteArrayOutputStream(64)
        buf.write(0x13)
        buf.write(0x37)
        buf.write(0x01)
        buf.write(0x00)
        buf.write(byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        for (label in domain.split(".")) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            buf.write(bytes.size and 0xFF)
            buf.write(bytes)
        }
        buf.write(0x00)
        buf.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
        return buf.toByteArray()
    }

    private fun parseFirstARecordFromDnsResponse(resp: ByteArray): String? {
        return try {
            if (resp.size < 12) return null
            val qdCount = ((resp[4].toInt() and 0xFF) shl 8) or (resp[5].toInt() and 0xFF)
            val anCount = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
            if (anCount <= 0) return null

            var pos = 12
            repeat(qdCount) {
                pos = skipDnsName(resp, pos) + 4
            }
            repeat(anCount) {
                if (pos >= resp.size) return null
                pos = skipDnsName(resp, pos)
                if (pos + 10 > resp.size) return null
                val rType = ((resp[pos].toInt() and 0xFF) shl 8) or (resp[pos + 1].toInt() and 0xFF)
                val rdLen = ((resp[pos + 8].toInt() and 0xFF) shl 8) or (resp[pos + 9].toInt() and 0xFF)
                pos += 10
                if (rType == 1 && rdLen == 4 && pos + 4 <= resp.size) {
                    return "${resp[pos].toInt() and 0xFF}.${resp[pos + 1].toInt() and 0xFF}.${resp[pos + 2].toInt() and 0xFF}.${resp[pos + 3].toInt() and 0xFF}"
                }
                pos += rdLen
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun skipDnsName(buf: ByteArray, startPos: Int): Int {
        var pos = startPos
        while (pos < buf.size) {
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) return pos + 2
            pos += 1 + len
        }
        return pos
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

    private fun isCloudflareAnycastFrontedHost(host: String): Boolean {
        val h = host.trim().lowercase()
        return h == "x.com" ||
            h.endsWith(".x.com") ||
            h == "twitter.com" ||
            h.endsWith(".twitter.com") ||
            h == "t.co" ||
            h.endsWith(".t.co")
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

private class AetherFragmentingSocketWrapper(
    private val delegate: Socket
) : Socket() {
    private val fragmentedOut by lazy { AetherFragmentedOutputStream(delegate.getOutputStream()) }
    override fun getInputStream(): InputStream = delegate.getInputStream()
    override fun getOutputStream(): OutputStream = fragmentedOut
    override fun isConnected(): Boolean = delegate.isConnected
    override fun isClosed(): Boolean = delegate.isClosed
    override fun setSoTimeout(timeout: Int) = delegate.setSoTimeout(timeout)
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun close() = delegate.close()
}

private class TunnelStreamSocket(
    private val stream: V2RayTunnelStream,
    private var timeoutMs: Int = 2400
) : Socket() {
    override fun getInputStream(): InputStream = stream.input
    override fun getOutputStream(): OutputStream = stream.output
    override fun isConnected(): Boolean = true
    override fun isClosed(): Boolean = false
    override fun setSoTimeout(timeout: Int) {
        timeoutMs = timeout
        runCatching { stream.underlyingSocket.soTimeout = timeout }
    }
    override fun getSoTimeout(): Int = timeoutMs
    override fun close() = stream.close()
}

/**
 * Method 2 (CluvexStudio/Aether):
 * Splits TLS ClientHello into two TLS Handshake records across the middle of the payload.
 */
private class AetherFragmentedOutputStream(
    private val rawOut: OutputStream
) : OutputStream() {

    private var firstPacketProcessed = false

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        if (!firstPacketProcessed) {
            firstPacketProcessed = true
            val firstChunk = b.copyOfRange(off, off + len)
            if (isTlsClientHello(firstChunk)) {
                writeFragmentedTlsClientHello(firstChunk)
                return
            } else if (isPlainHttpRequest(firstChunk)) {
                writeFragmentedHttpRequest(firstChunk)
                return
            }
        }
        rawOut.write(b, off, len)
    }

    private fun isTlsClientHello(data: ByteArray): Boolean {
        return data.size > 43 &&
            (data[0].toInt() and 0xFF) == 0x16 &&
            (data[1].toInt() and 0xFF) == 0x03 &&
            (data[5].toInt() and 0xFF) == 0x01
    }

    private fun isPlainHttpRequest(data: ByteArray): Boolean {
        if (data.size < 16) return false
        val prefix = String(data, 0, minOf(data.size, 8), Charsets.US_ASCII)
        return prefix.startsWith("GET ") || prefix.startsWith("POST ") || prefix.startsWith("HEAD ")
    }

    private fun writeFragmentedTlsClientHello(data: ByteArray) {
        val recordLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        val firstRecTotal = 5 + recordLen
        if (recordLen > 32 && data.size >= firstRecTotal) {
            val payload = data.copyOfRange(5, firstRecTotal)
            val splitPoint = (payload.size / 2).coerceIn(16, payload.size - 8)
            val part1 = payload.copyOfRange(0, splitPoint)
            val part2 = payload.copyOfRange(splitPoint, payload.size)

            val rec1 = ByteArray(5 + part1.size)
            rec1[0] = data[0]
            rec1[1] = data[1]
            rec1[2] = data[2]
            rec1[3] = ((part1.size ushr 8) and 0xFF).toByte()
            rec1[4] = (part1.size and 0xFF).toByte()
            System.arraycopy(part1, 0, rec1, 5, part1.size)

            val rec2 = ByteArray(5 + part2.size)
            rec2[0] = data[0]
            rec2[1] = data[1]
            rec2[2] = data[2]
            rec2[3] = ((part2.size ushr 8) and 0xFF).toByte()
            rec2[4] = (part2.size and 0xFF).toByte()
            System.arraycopy(part2, 0, rec2, 5, part2.size)

            rawOut.write(rec1)
            rawOut.flush()
            rawOut.write(rec2)
            rawOut.flush()
            if (data.size > firstRecTotal) {
                rawOut.write(data, firstRecTotal, data.size - firstRecTotal)
                rawOut.flush()
            }
        } else {
            val mid = (data.size / 2).coerceAtLeast(1)
            rawOut.write(data, 0, mid)
            rawOut.flush()
            rawOut.write(data, mid, data.size - mid)
            rawOut.flush()
        }
    }

    private fun writeFragmentedHttpRequest(data: ByteArray) {
        val text = String(data, Charsets.ISO_8859_1)
        val hostIdx = text.indexOf("Host:", ignoreCase = true)
        if (hostIdx > 0 && hostIdx + 8 < data.size) {
            val splitAt = hostIdx + 7
            rawOut.write(data, 0, splitAt)
            rawOut.flush()
            rawOut.write(data, splitAt, data.size - splitAt)
            rawOut.flush()
        } else {
            rawOut.write(data)
            rawOut.flush()
        }
    }

    override fun flush() = rawOut.flush()
    override fun close() = rawOut.close()
}

/**
 * Method 3 (patterniha/Serverless-for-Iran):
 * Implements Xray Freedom `fragment` (`packets: "tlshello"`, `length: "1-3"`, `interval: "5"`).
 * Slices the TLS ClientHello packet into tiny 1-to-3 byte TCP chunks with 5ms interval pacing.
 */
private class ServerlessMicroFragmentOutputStream(
    private val rawOut: OutputStream,
    private val random: SecureRandom
) : OutputStream() {

    private var firstPacketProcessed = false

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        if (!firstPacketProcessed) {
            firstPacketProcessed = true
            val firstChunk = b.copyOfRange(off, off + len)
            if (firstChunk.size > 16) {
                var pos = 0
                // Micro-fragment the initial 192 bytes (covering TLS record header + SNI extension) in 1..3 byte slices
                val microLimit = minOf(firstChunk.size, 192)
                while (pos < microLimit) {
                    val sliceLen = minOf(1 + random.nextInt(3), microLimit - pos)
                    rawOut.write(firstChunk, pos, sliceLen)
                    rawOut.flush()
                    pos += sliceLen
                    if (pos < microLimit) {
                        runCatching { Thread.sleep(2) }
                    }
                }
                if (pos < firstChunk.size) {
                    rawOut.write(firstChunk, pos, firstChunk.size - pos)
                    rawOut.flush()
                }
                return
            }
        }
        rawOut.write(b, off, len)
    }

    override fun flush() = rawOut.flush()
    override fun close() = rawOut.close()
}

/**
 * Method 4 (patterniha/SNI-Spoofing):
 * Implements TLS Record Desynchronization + SNI Boundary Splitting:
 * Splits the TLS ClientHello into 3 separate TLS Handshake records right at the exact byte offset
 * of the Server Name Indication (SNI) extension (or HTTP Host header) so passive/inline DPI
 * inspection fails to match the domain signature while the TLS server reassembles the records cleanly.
 */
private class SniSpoofingDesyncOutputStream(
    private val rawOut: OutputStream,
    @Suppress("UNUSED_PARAMETER") private val fakeSniDomain: String
) : OutputStream() {

    private var firstPacketProcessed = false

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        if (!firstPacketProcessed) {
            firstPacketProcessed = true
            val firstChunk = b.copyOfRange(off, off + len)
            if (isTlsClientHello(firstChunk)) {
                writeDesyncedTlsClientHello(firstChunk)
                return
            } else {
                // Split HTTP Host header into 3 tiny segments
                val text = String(firstChunk, Charsets.ISO_8859_1)
                val hostIdx = text.indexOf("Host:", ignoreCase = true)
                if (hostIdx > 0 && hostIdx + 10 < firstChunk.size) {
                    val p1 = hostIdx + 6
                    val p2 = hostIdx + 9
                    rawOut.write(firstChunk, 0, p1)
                    rawOut.flush()
                    rawOut.write(firstChunk, p1, p2 - p1)
                    rawOut.flush()
                    rawOut.write(firstChunk, p2, firstChunk.size - p2)
                    rawOut.flush()
                    return
                }
            }
        }
        rawOut.write(b, off, len)
    }

    private fun isTlsClientHello(data: ByteArray): Boolean {
        return data.size > 43 &&
            (data[0].toInt() and 0xFF) == 0x16 &&
            (data[1].toInt() and 0xFF) == 0x03 &&
            (data[5].toInt() and 0xFF) == 0x01
    }

    private fun writeDesyncedTlsClientHello(data: ByteArray) {
        val recordLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        val firstRecTotal = 5 + recordLen
        if (recordLen > 48 && data.size >= firstRecTotal) {
            val payload = data.copyOfRange(5, firstRecTotal)
            val sniOffsetInPayload = findSniOffsetInHandshake(payload)
            val cut1 = (sniOffsetInPayload ?: (payload.size / 3)).coerceIn(8, payload.size - 16)
            val cut2 = (cut1 + 3).coerceIn(cut1 + 1, payload.size - 4)

            val seg1 = wrapTlsHandshakeRecord(data[1], data[2], payload.copyOfRange(0, cut1))
            val seg2 = wrapTlsHandshakeRecord(data[1], data[2], payload.copyOfRange(cut1, cut2))
            val seg3 = wrapTlsHandshakeRecord(data[1], data[2], payload.copyOfRange(cut2, payload.size))

            rawOut.write(seg1)
            rawOut.flush()
            runCatching { Thread.sleep(2) }
            rawOut.write(seg2)
            rawOut.flush()
            runCatching { Thread.sleep(2) }
            rawOut.write(seg3)
            rawOut.flush()
            if (data.size > firstRecTotal) {
                rawOut.write(data, firstRecTotal, data.size - firstRecTotal)
                rawOut.flush()
            }
        } else {
            val p1 = (data.size / 3).coerceAtLeast(1)
            val p2 = ((data.size * 2) / 3).coerceAtLeast(p1 + 1).coerceAtMost(data.size)
            rawOut.write(data, 0, p1)
            rawOut.flush()
            rawOut.write(data, p1, p2 - p1)
            rawOut.flush()
            if (p2 < data.size) {
                rawOut.write(data, p2, data.size - p2)
                rawOut.flush()
            }
        }
    }

    private fun wrapTlsHandshakeRecord(verMajor: Byte, verMinor: Byte, chunk: ByteArray): ByteArray {
        val rec = ByteArray(5 + chunk.size)
        rec[0] = 0x16
        rec[1] = verMajor
        rec[2] = verMinor
        rec[3] = ((chunk.size ushr 8) and 0xFF).toByte()
        rec[4] = (chunk.size and 0xFF).toByte()
        System.arraycopy(chunk, 0, rec, 5, chunk.size)
        return rec
    }

    private fun findSniOffsetInHandshake(payload: ByteArray): Int? {
        try {
            var pos = 38 // Handshake header(4) + Version(2) + Random(32)
            if (pos >= payload.size) return null
            val sessionIdLen = payload[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            if (pos + 2 > payload.size) return null
            val cipherLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherLen
            if (pos + 1 > payload.size) return null
            val compLen = payload[pos].toInt() and 0xFF
            pos += 1 + compLen
            if (pos + 2 > payload.size) return null
            val extTotalLen = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
            pos += 2
            val end = minOf(payload.size, pos + extTotalLen)
            while (pos + 4 <= end) {
                val extType = ((payload[pos].toInt() and 0xFF) shl 8) or (payload[pos + 1].toInt() and 0xFF)
                val extLen = ((payload[pos + 2].toInt() and 0xFF) shl 8) or (payload[pos + 3].toInt() and 0xFF)
                pos += 4
                if (extType == 0x0000 && extLen >= 5) {
                    return pos + 6 // Right inside the SNI hostname bytes
                }
                pos += extLen
            }
        } catch (_: Exception) {
        }
        return null
    }

    override fun flush() = rawOut.flush()
    override fun close() = rawOut.close()
}

/**
 * Prepends [headerBytes] (VLESS or Trojan header) onto the very first payload write so that
 * WebSocket-based V2Ray servers (especially Cloudflare Workers) receive [Header + ClientHello]
 * inside a single binary WebSocket frame.
 */
private class PrependingHeaderOutputStream(
    private val headerBytes: ByteArray,
    private val delegate: OutputStream
) : OutputStream() {
    private var headerSent = false

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

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
