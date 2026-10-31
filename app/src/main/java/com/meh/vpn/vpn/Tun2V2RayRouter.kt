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
import java.io.ByteArrayOutputStream
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * User-space IPv4 TUN Packet Router (TUN2V2Ray):
 * - Intercepts all IPv4 UDP DNS queries (port 53), forwards them over TCP through the V2Ray tunnel
 *   to 1.1.1.1:53, caches resolved IP -> Domain mappings, and injects UDP DNS replies into TUN.
 * - Intercepts all IPv4 TCP connections (0.0.0.0/0), performs a user-space TCP handshake
 *   (SYN -> SYN-ACK -> ACK/DATA), extracts the TLS SNI or HTTP Host header (or cached DNS domain),
 *   and bridges the stream bi-directionally through [V2RayOutboundClient].
 */
class Tun2V2RayRouter(
    private val vpnService: VpnService,
    @Volatile var activeConfig: V2RayConfig
) {
    private val routerScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var readerJob: Job? = null
    private var tunOutStream: FileOutputStream? = null
    private val writeLock = Any()

    private val tcpSessions = ConcurrentHashMap<String, TcpNatSession>()
    private val dnsIpToDomainCache = ConcurrentHashMap<String, String>()
    private val ipIdCounter = AtomicInteger(1000)

    private var pooledDnsStream: V2RayTunnelStream? = null
    private var pooledDnsConfig: V2RayConfig? = null
    private val dnsTunnelLock = Any()

    fun start(tunFd: FileDescriptor) {
        stop()
        val tunIn = FileInputStream(tunFd)
        val tunOut = FileOutputStream(tunFd)
        tunOutStream = tunOut

        readerJob = routerScope.launch {
            val packetBuf = ByteArray(32767)
            while (isActive) {
                val readLen = try {
                    tunIn.read(packetBuf)
                } catch (_: Exception) {
                    break
                }
                if (readLen <= 20) continue

                val version = (packetBuf[0].toInt() ushr 4) and 0x0F
                if (version != 4) continue // IPv4 only

                val ihl = (packetBuf[0].toInt() and 0x0F) * 4
                if (readLen < ihl) continue

                val protocol = packetBuf[9].toInt() and 0xFF

                when (protocol) {
                    17 -> { // UDP
                        if (readLen >= ihl + 8) {
                            handleUdpPacket(packetBuf, readLen, ihl)
                        }
                    }
                    6 -> { // TCP
                        if (readLen >= ihl + 20) {
                            handleTcpPacket(packetBuf, readLen, ihl)
                        }
                    }
                }
            }
        }
    }

    private fun writeTunPacket(packet: ByteArray) {
        val out = tunOutStream ?: return
        synchronized(writeLock) {
            runCatching {
                out.write(packet)
                out.flush()
            }
        }
    }

    // =========================================================================
    // UDP DNS Handler (Port 53 over V2Ray TCP Tunnel + DNS IP->Domain Sniffer)
    // =========================================================================

    private fun handleUdpPacket(packet: ByteArray, packetLen: Int, ihl: Int) {
        val dstPort = readUInt16(packet, ihl + 2)
        if (dstPort != 53) {
            // Answer unhandled UDP (e.g. QUIC on 443) with ICMP Port Unreachable so browsers
            // fail over to TCP immediately instead of waiting for their UDP socket timeout.
            writeTunPacket(buildIcmpPortUnreachablePacket(packet, packetLen, ihl))
            return
        }

        val payloadOffset = ihl + 8
        val payloadLen = packetLen - payloadOffset
        if (payloadLen <= 12) return

        val dnsQuery = packet.copyOfRange(payloadOffset, packetLen)
        val queriedDomain = parseDnsQueryDomain(dnsQuery)

        routerScope.launch {
            runCatching {
                val dnsResp = executeDnsQuery(dnsQuery) ?: return@launch

                if (!queriedDomain.isNullOrEmpty()) {
                    extractDnsARecords(dnsResp, queriedDomain)
                }

                val udpRespPacket = buildIpv4UdpPacket(
                    srcIp = packet.copyOfRange(16, 20),
                    dstIp = packet.copyOfRange(12, 16),
                    srcPort = dstPort,
                    dstPort = readUInt16(packet, ihl),
                    payload = dnsResp
                )
                writeTunPacket(udpRespPacket)
            }
        }
    }

    private fun executeDnsQuery(dnsQuery: ByteArray): ByteArray? {
        synchronized(dnsTunnelLock) {
            for (attempt in 0..1) {
                try {
                    val stream = getOrCreateDnsTunnelLocked()
                    val framedReq = ByteArray(dnsQuery.size + 2)
                    framedReq[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
                    framedReq[1] = (dnsQuery.size and 0xFF).toByte()
                    System.arraycopy(dnsQuery, 0, framedReq, 2, dnsQuery.size)

                    stream.output.write(framedReq)
                    stream.output.flush()

                    val hi = stream.input.read()
                    val lo = stream.input.read()
                    if (hi == -1 || lo == -1) {
                        closeDnsTunnelLocked()
                        continue
                    }
                    val respLen = (hi shl 8) or lo
                    if (respLen !in 12..4096) {
                        closeDnsTunnelLocked()
                        continue
                    }

                    val dnsResp = ByteArray(respLen)
                    var total = 0
                    while (total < respLen) {
                        val r = stream.input.read(dnsResp, total, respLen - total)
                        if (r == -1) break
                        total += r
                    }
                    if (total == respLen) {
                        return dnsResp
                    }
                    closeDnsTunnelLocked()
                } catch (_: Exception) {
                    closeDnsTunnelLocked()
                }
            }
            return null
        }
    }

    private fun getOrCreateDnsTunnelLocked(): V2RayTunnelStream {
        val current = pooledDnsStream
        if (current != null && pooledDnsConfig == activeConfig) {
            return current
        }
        closeDnsTunnelLocked()
        val newStream = V2RayOutboundClient.openTunnelStream(
            config = activeConfig,
            targetHost = "1.1.1.1",
            targetPort = 53,
            vpnService = vpnService,
            connectTimeoutMs = 3500
        )
        pooledDnsStream = newStream
        pooledDnsConfig = activeConfig
        return newStream
    }

    private fun closeDnsTunnelLocked() {
        runCatching { pooledDnsStream?.close() }
        pooledDnsStream = null
        pooledDnsConfig = null
    }

    private fun parseDnsQueryDomain(dnsBytes: ByteArray): String? {
        return try {
            var pos = 12
            val labels = mutableListOf<String>()
            while (pos < dnsBytes.size) {
                val len = dnsBytes[pos].toInt() and 0xFF
                if (len == 0) break
                if ((len and 0xC0) != 0) break
                pos++
                if (pos + len > dnsBytes.size) return null
                labels.add(String(dnsBytes, pos, len, Charsets.US_ASCII))
                pos += len
            }
            if (labels.isEmpty()) null else labels.joinToString(".").lowercase()
        } catch (_: Exception) {
            null
        }
    }

    private fun extractDnsARecords(dnsResp: ByteArray, domain: String) {
        runCatching {
            if (dnsResp.size < 12) return
            val qdCount = readUInt16(dnsResp, 4)
            val anCount = readUInt16(dnsResp, 6)
            if (anCount <= 0) return

            var pos = 12
            // Skip Question section
            repeat(qdCount) {
                pos = skipDnsName(dnsResp, pos)
                pos += 4 // QTYPE + QCLASS
            }
            // Parse Answer section for Type A (1) records
            repeat(anCount) {
                if (pos >= dnsResp.size) return
                pos = skipDnsName(dnsResp, pos)
                if (pos + 10 > dnsResp.size) return
                val rType = readUInt16(dnsResp, pos)
                val rdLen = readUInt16(dnsResp, pos + 8)
                pos += 10
                if (rType == 1 && rdLen == 4 && pos + 4 <= dnsResp.size) {
                    val ipStr =
                        "${dnsResp[pos].toInt() and 0xFF}.${dnsResp[pos + 1].toInt() and 0xFF}.${dnsResp[pos + 2].toInt() and 0xFF}.${dnsResp[pos + 3].toInt() and 0xFF}"
                    dnsIpToDomainCache[ipStr] = domain
                }
                pos += rdLen
            }
        }
    }

    private fun skipDnsName(buf: ByteArray, startPos: Int): Int {
        var pos = startPos
        while (pos < buf.size) {
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) {
                return pos + 1
            }
            if ((len and 0xC0) == 0xC0) {
                return pos + 2
            }
            pos += 1 + len
        }
        return pos
    }

    // =========================================================================
    // TCP NAT Stack (Handles SYN, ACK, PSH+ACK, FIN, RST + TLS SNI Extraction)
    // =========================================================================

    private fun handleTcpPacket(packet: ByteArray, packetLen: Int, ihl: Int) {
        val srcIpBytes = packet.copyOfRange(12, 16)
        val dstIpBytes = packet.copyOfRange(16, 20)
        val srcIpStr = formatIpv4(srcIpBytes)
        val dstIpStr = formatIpv4(dstIpBytes)

        val srcPort = readUInt16(packet, ihl)
        val dstPort = readUInt16(packet, ihl + 2)
        val seqNum = readUInt32(packet, ihl + 4)
        val ackNum = readUInt32(packet, ihl + 8)
        val dataOffset = ((packet[ihl + 12].toInt() ushr 4) and 0x0F) * 4
        val flags = packet[ihl + 13].toInt() and 0x3F

        val isSyn = (flags and TCP_FLAG_SYN) != 0
        val isAck = (flags and TCP_FLAG_ACK) != 0
        val isFin = (flags and TCP_FLAG_FIN) != 0
        val isRst = (flags and TCP_FLAG_RST) != 0

        val payloadOffset = ihl + dataOffset
        val payloadLen = (packetLen - payloadOffset).coerceAtLeast(0)
        val sessionKey = "$srcIpStr:$srcPort->$dstIpStr:$dstPort"

        if (isRst) {
            tcpSessions.remove(sessionKey)?.closeQuietly()
            return
        }

        if (isSyn && !isAck) {
            // New outbound TCP connection from device
            tcpSessions.remove(sessionKey)?.closeQuietly()
            val session = TcpNatSession(
                key = sessionKey,
                clientIp = srcIpBytes,
                serverIp = dstIpBytes,
                serverIpStr = dstIpStr,
                clientPort = srcPort,
                serverPort = dstPort,
                initialClientSeq = seqNum
            )
            tcpSessions[sessionKey] = session
            session.onSynReceived()
            return
        }

        val session = tcpSessions[sessionKey] ?: return

        if (payloadLen > 0) {
            val payload = packet.copyOfRange(payloadOffset, packetLen)
            session.onClientDataReceived(seqNum, payload)
        } else if (isAck && !isFin) {
            session.onPureAckReceived(ackNum)
        }

        if (isFin) {
            session.onClientFinReceived(seqNum + payloadLen)
        }
    }

    private inner class TcpNatSession(
        val key: String,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val serverIpStr: String,
        val clientPort: Int,
        val serverPort: Int,
        initialClientSeq: Long
    ) {
        @Volatile
        private var clientNextSeq: Long = (initialClientSeq + 1) and 0xFFFFFFFFL

        @Volatile
        private var mySeq: Long = (System.nanoTime() and 0x7FFFFFFFL)

        @Volatile
        private var tunnelStream: V2RayTunnelStream? = null

        @Volatile
        private var tunnelConnected = false

        @Volatile
        private var closed = false

        private val pendingPayloads = ByteArrayOutputStream()
        private var connectJob: Job? = null

        fun onSynReceived() {
            // Send SYN + ACK back to TUN immediately so the client sends its first data packet (TLS ClientHello / HTTP)
            val synAckPacket = buildIpv4TcpPacket(
                srcIp = serverIp,
                dstIp = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = mySeq,
                ack = clientNextSeq,
                flags = TCP_FLAG_SYN or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            mySeq = (mySeq + 1) and 0xFFFFFFFFL
            writeTunPacket(synAckPacket)
        }

        @Synchronized
        fun onPureAckReceived(@Suppress("UNUSED_PARAMETER") ackNum: Long) {
            // Handshake ACK completed; if port is not 80/443, we can also initiate connection right away
            if (serverPort != 443 && serverPort != 80 && connectJob == null && !closed) {
                val targetHost = dnsIpToDomainCache[serverIpStr] ?: serverIpStr
                startRemoteTunnel(targetHost)
            }
        }

        @Synchronized
        fun onClientDataReceived(seqNum: Long, data: ByteArray) {
            if (closed) return

            // Update ACK sequence and immediately ACK the client's data packet
            if (seqNum == clientNextSeq) {
                clientNextSeq = (clientNextSeq + data.size) and 0xFFFFFFFFL
            } else if (isSeqNewer(seqNum + data.size, clientNextSeq)) {
                clientNextSeq = (seqNum + data.size) and 0xFFFFFFFFL
            }

            val ackPacket = buildIpv4TcpPacket(
                srcIp = serverIp,
                dstIp = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = mySeq,
                ack = clientNextSeq,
                flags = TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            writeTunPacket(ackPacket)

            val activeTunnel = tunnelStream
            if (tunnelConnected && activeTunnel != null) {
                routerScope.launch {
                    try {
                        activeTunnel.output.write(data)
                        activeTunnel.output.flush()
                    } catch (_: Exception) {
                        sendResetAndClose()
                    }
                }
            } else {
                pendingPayloads.write(data)
                if (connectJob == null) {
                    val buffered = pendingPayloads.toByteArray()
                    val sniOrHost = extractTlsSni(buffered)
                        ?: extractHttpHost(buffered)
                        ?: dnsIpToDomainCache[serverIpStr]
                        ?: serverIpStr
                    startRemoteTunnel(sniOrHost)
                }
            }
        }

        private fun startRemoteTunnel(targetHost: String) {
            connectJob = routerScope.launch {
                try {
                    val stream = V2RayOutboundClient.openTunnelStream(
                        config = activeConfig,
                        targetHost = targetHost,
                        targetPort = serverPort,
                        vpnService = vpnService,
                        connectTimeoutMs = 5000
                    )
                    val initialBytes: ByteArray
                    synchronized(this@TcpNatSession) {
                        if (closed) {
                            stream.close()
                            return@launch
                        }
                        tunnelStream = stream
                        tunnelConnected = true
                        initialBytes = pendingPayloads.toByteArray()
                        pendingPayloads.reset()
                    }

                    if (initialBytes.isNotEmpty()) {
                        stream.output.write(initialBytes)
                        stream.output.flush()
                    }

                    // Downlink loop: read from V2Ray tunnel and inject TCP PSH+ACK segments into TUN
                    val readBuf = ByteArray(1360) // Safe MSS inside 1500 MTU
                    while (isActive && !closed) {
                        val r = stream.input.read(readBuf)
                        if (r == -1) break
                        if (r > 0) {
                            val chunk = readBuf.copyOfRange(0, r)
                            val pshAck = buildIpv4TcpPacket(
                                srcIp = serverIp,
                                dstIp = clientIp,
                                srcPort = serverPort,
                                dstPort = clientPort,
                                seq = mySeq,
                                ack = clientNextSeq,
                                flags = TCP_FLAG_PSH or TCP_FLAG_ACK,
                                payload = chunk
                            )
                            mySeq = (mySeq + r) and 0xFFFFFFFFL
                            writeTunPacket(pshAck)
                        }
                    }

                    // Remote closed cleanly: send FIN+ACK
                    if (!closed) {
                        val finAck = buildIpv4TcpPacket(
                            srcIp = serverIp,
                            dstIp = clientIp,
                            srcPort = serverPort,
                            dstPort = clientPort,
                            seq = mySeq,
                            ack = clientNextSeq,
                            flags = TCP_FLAG_FIN or TCP_FLAG_ACK,
                            payload = ByteArray(0)
                        )
                        mySeq = (mySeq + 1) and 0xFFFFFFFFL
                        writeTunPacket(finAck)
                        closeQuietly()
                    }
                } catch (_: Exception) {
                    sendResetAndClose()
                }
            }
        }

        @Synchronized
        fun onClientFinReceived(finSeq: Long) {
            if (closed) return
            clientNextSeq = (finSeq + 1) and 0xFFFFFFFFL
            val finAck = buildIpv4TcpPacket(
                srcIp = serverIp,
                dstIp = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = mySeq,
                ack = clientNextSeq,
                flags = TCP_FLAG_FIN or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            mySeq = (mySeq + 1) and 0xFFFFFFFFL
            writeTunPacket(finAck)
            closeQuietly()
        }

        private fun sendResetAndClose() {
            if (!closed) {
                val rstPacket = buildIpv4TcpPacket(
                    srcIp = serverIp,
                    dstIp = clientIp,
                    srcPort = serverPort,
                    dstPort = clientPort,
                    seq = mySeq,
                    ack = clientNextSeq,
                    flags = TCP_FLAG_RST or TCP_FLAG_ACK,
                    payload = ByteArray(0)
                )
                writeTunPacket(rstPacket)
            }
            closeQuietly()
        }

        fun closeQuietly() {
            closed = true
            tcpSessions.remove(key)
            connectJob?.cancel()
            runCatching { tunnelStream?.close() }
            tunnelStream = null
        }
    }

    /**
     * Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello record if present.
     */
    private fun extractTlsSni(data: ByteArray): String? {
        try {
            if (data.size < 43) return null
            // ContentType == Handshake (0x16), Version major == 0x03, HandshakeType == ClientHello (0x01)
            if ((data[0].toInt() and 0xFF) != 0x16) return null
            if ((data[1].toInt() and 0xFF) != 0x03) return null
            if ((data[5].toInt() and 0xFF) != 0x01) return null

            var pos = 43 // Skip TLS record header(5) + Handshake header(4) + ClientVersion(2) + Random(32)
            if (pos >= data.size) return null

            // Session ID
            val sessionIdLen = data[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            if (pos + 2 > data.size) return null

            // Cipher Suites
            val cipherSuitesLen = readUInt16(data, pos)
            pos += 2 + cipherSuitesLen
            if (pos + 1 > data.size) return null

            // Compression Methods
            val compMethodsLen = data[pos].toInt() and 0xFF
            pos += 1 + compMethodsLen
            if (pos + 2 > data.size) return null

            // Extensions Length
            val extensionsLen = readUInt16(data, pos)
            pos += 2
            val extensionsEnd = minOf(data.size, pos + extensionsLen)

            while (pos + 4 <= extensionsEnd) {
                val extType = readUInt16(data, pos)
                val extLen = readUInt16(data, pos + 2)
                pos += 4
                if (pos + extLen > extensionsEnd) break

                if (extType == 0x0000 && extLen >= 5) { // server_name extension
                    val nameType = data[pos + 2].toInt() and 0xFF
                    val nameLen = readUInt16(data, pos + 3)
                    if (nameType == 0 && pos + 5 + nameLen <= extensionsEnd) {
                        val sni = String(data, pos + 5, nameLen, Charsets.US_ASCII).trim()
                        if (sni.isNotEmpty()) return sni
                    }
                }
                pos += extLen
            }
        } catch (_: Exception) {
        }
        return null
    }

    private fun extractHttpHost(data: ByteArray): String? {
        return try {
            val headLen = minOf(data.size, 512)
            val str = String(data, 0, headLen, Charsets.US_ASCII)
            if (!str.startsWith("GET ") && !str.startsWith("POST ") && !str.startsWith("HEAD ")) {
                return null
            }
            for (line in str.lineSequence()) {
                if (line.startsWith("Host:", ignoreCase = true)) {
                    val host = line.substringAfter(":").trim().substringBefore(":")
                    if (host.isNotEmpty()) return host
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    // =========================================================================
    // Packet Builders & Checksums
    // =========================================================================

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val out = ByteArray(totalLen)

        writeIpv4Header(out, totalLen, 17, srcIp, dstIp)

        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()
        val udpLen = 8 + payload.size
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0
        out[27] = 0

        System.arraycopy(payload, 0, out, 28, payload.size)
        return out
    }

    /**
     * Builds an RFC 792 ICMP Destination Unreachable / Port Unreachable (Type 3, Code 3)
     * quoting the original IP header plus the first 8 bytes of its UDP header.
     */
    private fun buildIcmpPortUnreachablePacket(originalPacket: ByteArray, originalLen: Int, ihl: Int): ByteArray {
        val quotedLen = (ihl + 8).coerceAtMost(originalLen)
        val icmpLen = 8 + quotedLen
        val totalLen = 20 + icmpLen
        val out = ByteArray(totalLen)

        writeIpv4Header(
            out = out,
            totalLen = totalLen,
            protocol = 1, // ICMP
            srcIp = originalPacket.copyOfRange(16, 20),
            dstIp = originalPacket.copyOfRange(12, 16)
        )

        // ICMP header: Type (3), Code (3), Checksum, 4 unused bytes
        out[20] = 3
        out[21] = 3
        out[22] = 0
        out[23] = 0
        out[24] = 0
        out[25] = 0
        out[26] = 0
        out[27] = 0

        System.arraycopy(originalPacket, 0, out, 28, quotedLen)

        // ICMP checksum over message header + quoted payload (no pseudo-header)
        var sum = 0
        var offset = 20
        while (offset < totalLen - 1) {
            sum += readUInt16(out, offset)
            offset += 2
        }
        if (offset < totalLen) {
            sum += (out[offset].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        out[22] = ((checksum ushr 8) and 0xFF).toByte()
        out[23] = (checksum and 0xFF).toByte()

        return out
    }

    private fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val isSyn = (flags and TCP_FLAG_SYN) != 0
        val tcpHeaderLen = if (isSyn) 24 else 20 // Include 4-byte MSS option on SYN-ACK
        val totalLen = 20 + tcpHeaderLen + payload.size
        val out = ByteArray(totalLen)

        writeIpv4Header(out, totalLen, 6, srcIp, dstIp)

        // TCP Header
        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()

        writeUInt32(out, 24, seq)
        writeUInt32(out, 28, ack)

        val dataOffsetWords = tcpHeaderLen / 4
        out[32] = ((dataOffsetWords shl 4) and 0xF0).toByte()
        out[33] = (flags and 0x3F).toByte()

        // Window size (65535)
        out[34] = 0xFF.toByte()
        out[35] = 0xFF.toByte()

        // Checksum (36..37) & Urgent Pointer (38..39)
        out[36] = 0
        out[37] = 0
        out[38] = 0
        out[39] = 0

        if (isSyn) {
            // TCP Option: Maximum Segment Size (Kind=2, Len=4, MSS=1360 = 0x0550)
            out[40] = 2
            out[41] = 4
            out[42] = 0x05
            out[43] = 0x50
        }

        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, out, 20 + tcpHeaderLen, payload.size)
        }

        // Compute TCP Pseudo-Header + Segment Checksum
        val tcpSegmentLen = tcpHeaderLen + payload.size
        var sum = 0
        // Pseudo-header: SrcIP(4) + DstIP(4) + Zero(1) + Proto(6) + TCP Length(2)
        for (i in 12 until 20 step 2) {
            sum += readUInt16(out, i)
        }
        sum += 6
        sum += tcpSegmentLen

        val tcpStart = 20
        var i = 0
        while (i < tcpSegmentLen - 1) {
            sum += readUInt16(out, tcpStart + i)
            i += 2
        }
        if (i < tcpSegmentLen) {
            sum += (out[tcpStart + i].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val tcpChecksum = sum.inv() and 0xFFFF
        out[36] = ((tcpChecksum ushr 8) and 0xFF).toByte()
        out[37] = (tcpChecksum and 0xFF).toByte()

        return out
    }

    private fun writeIpv4Header(
        out: ByteArray,
        totalLen: Int,
        protocol: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ) {
        out[0] = 0x45.toByte()
        out[1] = 0x00
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        val id = ipIdCounter.incrementAndGet() and 0xFFFF
        out[4] = ((id ushr 8) and 0xFF).toByte()
        out[5] = (id and 0xFF).toByte()
        out[6] = 0x40.toByte() // DF
        out[7] = 0x00
        out[8] = 64.toByte()   // TTL
        out[9] = (protocol and 0xFF).toByte()
        out[10] = 0
        out[11] = 0

        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)

        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += readUInt16(out, i)
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        out[10] = ((checksum ushr 8) and 0xFF).toByte()
        out[11] = (checksum and 0xFF).toByte()
    }

    private fun readUInt16(buf: ByteArray, offset: Int): Int {
        return ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
    }

    private fun readUInt32(buf: ByteArray, offset: Int): Long {
        return ((buf[offset].toLong() and 0xFFL) shl 24) or
            ((buf[offset + 1].toLong() and 0xFFL) shl 16) or
            ((buf[offset + 2].toLong() and 0xFFL) shl 8) or
            (buf[offset + 3].toLong() and 0xFFL)
    }

    private fun writeUInt32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value ushr 24) and 0xFFL).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFFL).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFFL).toByte()
        buf[offset + 3] = (value and 0xFFL).toByte()
    }

    private fun isSeqNewer(a: Long, b: Long): Boolean {
        val diff = ((a - b) and 0xFFFFFFFFL).toInt()
        return diff > 0
    }

    private fun formatIpv4(ip: ByteArray): String {
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }

    fun stop() {
        readerJob?.cancel()
        readerJob = null
        tcpSessions.values.forEach { it.closeQuietly() }
        tcpSessions.clear()
        tunOutStream = null
        synchronized(dnsTunnelLock) {
            closeDnsTunnelLocked()
        }
    }

    fun destroy() {
        stop()
        routerScope.cancel()
    }

    companion object {
        private const val TCP_FLAG_FIN = 0x01
        private const val TCP_FLAG_SYN = 0x02
        private const val TCP_FLAG_RST = 0x04
        private const val TCP_FLAG_PSH = 0x08
        private const val TCP_FLAG_ACK = 0x10
    }
}
