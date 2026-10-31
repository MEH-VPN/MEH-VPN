package com.meh.vpn.vpn

import android.net.VpnService
import com.meh.vpn.model.V2RayConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI

/**
 * Runs a local HTTP/HTTPS CONNECT & SOCKS5 Proxy Server backed by [V2RayOutboundClient],
 * plus a user-space TUN DNS/IPv4 bridge so device traffic routes through the active V2Ray server.
 */
class V2RayLocalProxyServer(
    private val vpnService: VpnService,
    @Volatile var activeConfig: V2RayConfig
) {
    private val proxyScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null
    private var tunBridgeJob: Job? = null

    var listeningPort: Int = 10809
        private set

    fun updateConfig(newConfig: V2RayConfig) {
        activeConfig = newConfig
    }

    fun start(): Int {
        stop()
        val boundSocket = runCatching {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 10809), 128)
            }
        }.getOrElse {
            ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        }

        serverSocket = boundSocket
        listeningPort = boundSocket.localPort

        acceptJob = proxyScope.launch {
            while (isActive && !boundSocket.isClosed) {
                val clientSocket = runCatching { boundSocket.accept() }.getOrNull() ?: break
                launch {
                    handleClientConnection(clientSocket)
                }
            }
        }
        return listeningPort
    }

    /**
     * Starts a non-blocking TUN interface loop that answers IPv4 UDP DNS queries (port 53)
     * through the V2Ray tunnel over TCP DNS (1.1.1.1:53) so DNS resolution is never poisoned.
     */
    fun attachTunDescriptor(tunFd: FileDescriptor) {
        tunBridgeJob?.cancel()
        tunBridgeJob = proxyScope.launch {
            val tunIn = FileInputStream(tunFd)
            val tunOut = FileOutputStream(tunFd)
            val packetBuf = ByteArray(32767)

            while (isActive) {
                val length = try {
                    tunIn.read(packetBuf)
                } catch (_: Exception) {
                    break
                }
                if (length <= 0) continue

                val packetCopy = packetBuf.copyOfRange(0, length)
                // Check if IPv4 (version == 4) and UDP (protocol == 17)
                val version = (packetCopy[0].toInt() ushr 4) and 0x0F
                if (version == 4 && length >= 28) {
                    val ihl = (packetCopy[0].toInt() and 0x0F) * 4
                    val protocol = packetCopy[9].toInt() and 0xFF
                    if (protocol == 17 && length >= ihl + 8) {
                        val dstPort = ((packetCopy[ihl + 2].toInt() and 0xFF) shl 8) or
                            (packetCopy[ihl + 3].toInt() and 0xFF)
                        if (dstPort == 53) {
                            launch {
                                handleTunUdpDnsPacket(packetCopy, ihl, tunOut)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun handleTunUdpDnsPacket(
        ipv4Packet: ByteArray,
        ihl: Int,
        tunOut: FileOutputStream
    ) {
        runCatching {
            val udpHeaderLen = 8
            val dnsPayloadOffset = ihl + udpHeaderLen
            val dnsPayloadLen = ipv4Packet.size - dnsPayloadOffset
            if (dnsPayloadLen <= 0) return

            val dnsQuery = ipv4Packet.copyOfRange(dnsPayloadOffset, ipv4Packet.size)

            // Forward DNS query over TCP to 1.1.1.1:53 through our V2Ray tunnel
            V2RayOutboundClient.openTunnelStream(
                config = activeConfig,
                targetHost = "1.1.1.1",
                targetPort = 53,
                vpnService = vpnService,
                connectTimeoutMs = 3500
            ).use { tunnel ->
                // TCP DNS prefixes the query with a 2-byte big-endian length
                val tcpDnsReq = ByteArray(dnsQuery.size + 2)
                tcpDnsReq[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
                tcpDnsReq[1] = (dnsQuery.size and 0xFF).toByte()
                System.arraycopy(dnsQuery, 0, tcpDnsReq, 2, dnsQuery.size)

                tunnel.output.write(tcpDnsReq)
                tunnel.output.flush()

                val lenHi = tunnel.input.read()
                val lenLo = tunnel.input.read()
                if (lenHi == -1 || lenLo == -1) return
                val respLen = (lenHi shl 8) or lenLo
                if (respLen !in 1..4096) return

                val dnsResp = ByteArray(respLen)
                var readTotal = 0
                while (readTotal < respLen) {
                    val r = tunnel.input.read(dnsResp, readTotal, respLen - readTotal)
                    if (r == -1) break
                    readTotal += r
                }
                if (readTotal < respLen) return

                val responseIpPacket = buildIpv4UdpResponsePacket(
                    requestPacket = ipv4Packet,
                    requestIhl = ihl,
                    udpPayload = dnsResp
                )
                synchronized(tunOut) {
                    tunOut.write(responseIpPacket)
                    tunOut.flush()
                }
            }
        }
    }

    private fun buildIpv4UdpResponsePacket(
        requestPacket: ByteArray,
        requestIhl: Int,
        udpPayload: ByteArray
    ): ByteArray {
        val totalLen = 20 + 8 + udpPayload.size
        val out = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        out[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
        out[1] = 0x00
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0x00
        out[5] = 0x00
        out[6] = 0x40.toByte() // Don't Fragment
        out[7] = 0x00
        out[8] = 64.toByte()   // TTL
        out[9] = 17.toByte()   // Protocol = UDP (17)

        // Swap Source IP and Destination IP from request
        System.arraycopy(requestPacket, 16, out, 12, 4) // New Src IP = Old Dst IP
        System.arraycopy(requestPacket, 12, out, 16, 4) // New Dst IP = Old Src IP

        // Compute IPv4 header checksum
        var sum = 0
        for (i in 0 until 20 step 2) {
            val word = ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
            sum += word
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        out[10] = ((checksum ushr 8) and 0xFF).toByte()
        out[11] = (checksum and 0xFF).toByte()

        // UDP Header (8 bytes): Swap Src Port & Dst Port
        out[20] = requestPacket[requestIhl + 2]
        out[21] = requestPacket[requestIhl + 3]
        out[22] = requestPacket[requestIhl]
        out[23] = requestPacket[requestIhl + 1]
        val udpLen = 8 + udpPayload.size
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0 // UDP checksum optional in IPv4 (0 = none)
        out[27] = 0

        System.arraycopy(udpPayload, 0, out, 28, udpPayload.size)
        return out
    }

    private fun handleClientConnection(clientSocket: Socket) {
        try {
            clientSocket.tcpNoDelay = true
            clientSocket.soTimeout = 30000
            val clientIn = clientSocket.getInputStream()
            val clientOut = BufferedOutputStream(clientSocket.getOutputStream())

            val firstByte = clientIn.read()
            if (firstByte == -1) {
                clientSocket.close()
                return
            }

            // Detect SOCKS5 (0x05) vs HTTP/HTTPS Proxy
            if (firstByte == 0x05) {
                handleSocks5Client(clientSocket, clientIn, clientOut)
            } else {
                handleHttpProxyClient(firstByte, clientSocket, clientIn, clientOut)
            }
        } catch (_: Exception) {
            runCatching { clientSocket.close() }
        }
    }

    private fun handleSocks5Client(
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val nMethods = clientIn.read()
        if (nMethods <= 0) return
        val methods = ByteArray(nMethods)
        readExact(clientIn, methods)

        // Reply: SOCKS5 (0x05), No Auth (0x00)
        clientOut.write(byteArrayOf(0x05, 0x00))
        clientOut.flush()

        // Read SOCKS5 request: VER(1) CMD(1) RSV(1) ATYP(1)
        val header = ByteArray(4)
        readExact(clientIn, header)
        val cmd = header[1].toInt() and 0xFF
        if (cmd != 0x01) { // Only CONNECT supported
            clientSocket.close()
            return
        }

        val targetHost: String = when (header[3].toInt() and 0xFF) {
            0x01 -> { // IPv4
                val ip = ByteArray(4)
                readExact(clientIn, ip)
                "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
            }
            0x03 -> { // Domain
                val len = clientIn.read()
                val domain = ByteArray(len)
                readExact(clientIn, domain)
                String(domain, Charsets.UTF_8)
            }
            0x04 -> { // IPv6
                val ip6 = ByteArray(16)
                readExact(clientIn, ip6)
                InetAddress.getByAddress(ip6).hostAddress ?: return
            }
            else -> return
        }

        val portHi = clientIn.read()
        val portLo = clientIn.read()
        val targetPort = (portHi shl 8) or portLo

        V2RayOutboundClient.openTunnelStream(
            config = activeConfig,
            targetHost = targetHost,
            targetPort = targetPort,
            vpnService = vpnService
        ).use { tunnel ->
            // Send SOCKS5 success reply
            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOut.flush()
            relayBidirectional(clientSocket, clientIn, clientOut, tunnel)
        }
    }

    private fun handleHttpProxyClient(
        firstByte: Int,
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream
    ) {
        val headerBuf = ByteArrayOutputStream(512)
        headerBuf.write(firstByte)

        var matchState = if (firstByte == '\r'.code) 1 else 0
        while (headerBuf.size() < 16384) {
            val b = clientIn.read()
            if (b == -1) return
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

        val fullHeader = headerBuf.toString("US-ASCII")
        val firstLine = fullHeader.lineSequence().firstOrNull()?.trim() ?: return
        val parts = firstLine.split(" ")
        if (parts.size < 2) return

        val method = parts[0].uppercase()
        val targetUri = parts[1]

        if (method == "CONNECT") {
            val host = targetUri.substringBeforeLast(":", targetUri)
            val port = targetUri.substringAfterLast(":", "443").toIntOrNull() ?: 443

            V2RayOutboundClient.openTunnelStream(
                config = activeConfig,
                targetHost = host,
                targetPort = port,
                vpnService = vpnService
            ).use { tunnel ->
                val established = "HTTP/1.1 200 Connection Established\r\n\r\n"
                clientOut.write(established.toByteArray(Charsets.US_ASCII))
                clientOut.flush()
                relayBidirectional(clientSocket, clientIn, clientOut, tunnel)
            }
        } else {
            // Plain HTTP request (GET/POST http://host:port/path)
            val parsedUri = runCatching { URI(targetUri) }.getOrNull()
            val host = parsedUri?.host ?: extractHostHeader(fullHeader) ?: return
            val port = if (parsedUri != null && parsedUri.port != -1) parsedUri.port else 80
            val relativePath = if (parsedUri != null) {
                val p = parsedUri.rawPath.ifEmpty { "/" }
                val q = parsedUri.rawQuery
                if (q.isNullOrEmpty()) p else "$p?$q"
            } else {
                targetUri
            }

            val rewrittenHeader = fullHeader.replaceFirst(
                "$method $targetUri ",
                "$method $relativePath "
            )

            V2RayOutboundClient.openTunnelStream(
                config = activeConfig,
                targetHost = host,
                targetPort = port,
                vpnService = vpnService
            ).use { tunnel ->
                tunnel.output.write(rewrittenHeader.toByteArray(Charsets.US_ASCII))
                tunnel.output.flush()
                relayBidirectional(clientSocket, clientIn, clientOut, tunnel)
            }
        }
    }

    private fun extractHostHeader(headers: String): String? {
        for (line in headers.lineSequence()) {
            if (line.startsWith("Host:", ignoreCase = true)) {
                return line.substringAfter(":").trim().substringBefore(":")
            }
        }
        return null
    }

    private fun relayBidirectional(
        clientSocket: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        tunnel: V2RayTunnelStream
    ) {
        val uplinkJob = proxyScope.launch {
            try {
                val buf = ByteArray(16384)
                while (isActive) {
                    val r = clientIn.read(buf)
                    if (r == -1) break
                    tunnel.output.write(buf, 0, r)
                    tunnel.output.flush()
                }
            } catch (_: Exception) {
            } finally {
                runCatching { tunnel.output.flush() }
            }
        }

        try {
            val buf = ByteArray(16384)
            while (true) {
                val r = tunnel.input.read(buf)
                if (r == -1) break
                clientOut.write(buf, 0, r)
                clientOut.flush()
            }
        } catch (_: Exception) {
        } finally {
            uplinkJob.cancel()
            runCatching { tunnel.close() }
            runCatching { clientSocket.close() }
        }
    }

    private fun readExact(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val r = input.read(buf, off, buf.size - off)
            if (r == -1) throw EOFException()
            off += r
        }
    }

    fun stop() {
        acceptJob?.cancel()
        acceptJob = null
        tunBridgeJob?.cancel()
        tunBridgeJob = null
        runCatching { serverSocket?.close() }
        serverSocket = null
    }

    fun destroy() {
        stop()
        proxyScope.cancel()
    }
}
