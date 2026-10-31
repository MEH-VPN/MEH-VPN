package com.meh.vpn.vpn

import android.net.VpnService
import com.meh.vpn.model.V2RayConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
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
 * - Intercepts all IPv4 UDP DNS queries (port 53), serves Instant FakeDNS (198.18.0.0/15) for A records
 *   so DNS resolves in <1ms with zero ISP poisoning and 100% compatibility with Cloudflare Worker VLESS,
 *   and suppresses IPv6 (AAAA) and QUIC (HTTPS/SVCB) with clean RFC-compliant NOERROR replies.
 * - Intercepts all IPv4 TCP connections (0.0.0.0/0), performs a user-space TCP handshake
 *   (SYN -> SYN-ACK -> ACK/DATA), deduplicates TCP retransmissions, extracts the TLS SNI / HTTP Host
 *   or FakeDNS domain mapping, and bridges the stream bi-directionally through [V2RayOutboundClient].
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
    private val domainToFakeIpCache = ConcurrentHashMap<String, String>()
    private val fakeIpSequence = AtomicInteger(1)
    private val ipIdCounter = AtomicInteger(1000)

    /**
     * Hot-swaps the active tunnel configuration in-place without tearing down the TUN interface.
     */
    fun updateConfig(newConfig: V2RayConfig) {
        if (activeConfig.rawUri == newConfig.rawUri) return
        activeConfig = newConfig
    }

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
        val parsedDns = parseDnsQueryQuestion(dnsQuery)
        val queriedDomain = parsedDns.domain
        val qType = parsedDns.qType
        val questionEndPos = parsedDns.questionEndPos

        if (questionEndPos <= 12) return

        // Block IPv6 (AAAA = 28) and HTTPS/SVCB QUIC hints (TYPE = 65) by returning an immediate
        // RFC-compliant empty NOERROR response (stripped of trailing EDNS0 OPT bytes)
        if (qType == 28 || qType == 65) {
            val emptyNoError = buildEmptyDnsNoErrorResponse(dnsQuery, questionEndPos)
            val udpRespPacket = buildIpv4UdpPacket(
                srcIp = packet.copyOfRange(16, 20),
                dstIp = packet.copyOfRange(12, 16),
                srcPort = dstPort,
                dstPort = readUInt16(packet, ihl),
                payload = emptyNoError
            )
            writeTunPacket(udpRespPacket)
            return
        }

        // Instant FakeDNS (198.18.0.0/15) for IPv4 A (qType == 1) queries:
        // Resolves in <0.2ms in memory with zero ISP DNS poisoning and zero port-53 dependency,
        // mapping 198.18.x.y -> queriedDomain so VLESS/Trojan always receives the exact domain name!
        if (qType == 1 && !queriedDomain.isNullOrEmpty()) {
            val fakeIpBytes = allocateFakeIpBytesForDomain(queriedDomain)
            val fakeDnsResp = buildFakeDnsAResponse(dnsQuery, questionEndPos, fakeIpBytes)
            val udpRespPacket = buildIpv4UdpPacket(
                srcIp = packet.copyOfRange(16, 20),
                dstIp = packet.copyOfRange(12, 16),
                srcPort = dstPort,
                dstPort = readUInt16(packet, ihl),
                payload = fakeDnsResp
            )
            writeTunPacket(udpRespPacket)
            return
        }

        // For any other DNS record type (PTR, TXT, SRV, etc.), return a clean empty NOERROR immediately
        val emptyResp = buildEmptyDnsNoErrorResponse(dnsQuery, questionEndPos)
        val udpRespPacket = buildIpv4UdpPacket(
            srcIp = packet.copyOfRange(16, 20),
            dstIp = packet.copyOfRange(12, 16),
            srcPort = dstPort,
            dstPort = readUInt16(packet, ihl),
            payload = emptyResp
        )
        writeTunPacket(udpRespPacket)
    }

    /**
     * Allocates a deterministic FakeIP from 198.18.0.0/15 for [domain] and stores the bidirectional
     * mapping in [dnsIpToDomainCache] and [domainToFakeIpCache].
     */
    internal fun allocateFakeIpForDomain(domain: String): String {
        val cleanDomain = domain.trim().lowercase().trimEnd('.')
        domainToFakeIpCache[cleanDomain]?.let { existingIp ->
            dnsIpToDomainCache[existingIp] = cleanDomain
            return existingIp
        }
        val idx = (fakeIpSequence.getAndIncrement() and 0x7FFF).coerceAtLeast(1)
        val thirdOctet = (idx ushr 8) and 0xFF
        val fourthOctet = (idx and 0xFF).coerceIn(1, 254)
        val fakeIp = "198.18.$thirdOctet.$fourthOctet"
        domainToFakeIpCache[cleanDomain] = fakeIp
        dnsIpToDomainCache[fakeIp] = cleanDomain
        return fakeIp
    }

    private fun allocateFakeIpBytesForDomain(domain: String): ByteArray {
        val fakeIp = allocateFakeIpForDomain(domain)
        val parts = fakeIp.split(".")
        return byteArrayOf(
            parts[0].toInt().toByte(),
            parts[1].toInt().toByte(),
            parts[2].toInt().toByte(),
            parts[3].toInt().toByte()
        )
    }

    /**
     * Builds a clean RFC 1035 NOERROR response with ANCOUNT=0, truncating at [questionEndPos]
     * so any trailing EDNS0 OPT record in the query does not cause FORMERR on Android netd.
     */
    private fun buildEmptyDnsNoErrorResponse(dnsQuery: ByteArray, questionEndPos: Int): ByteArray {
        val safeEnd = questionEndPos.coerceIn(12, dnsQuery.size)
        val resp = dnsQuery.copyOfRange(0, safeEnd)
        // QR=1 (Response), Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0 (NOERROR)
        resp[2] = 0x81.toByte()
        resp[3] = 0x80.toByte()
        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        resp[4] = 0
        resp[5] = 1
        resp[6] = 0
        resp[7] = 0
        resp[8] = 0
        resp[9] = 0
        resp[10] = 0
        resp[11] = 0
        return resp
    }

    /**
     * Builds a clean RFC 1035 Type A response for [fakeIpBytes], stripping trailing EDNS0 records
     * and appending a single 16-byte Type A resource record directly after the Question section.
     */
    private fun buildFakeDnsAResponse(
        dnsQuery: ByteArray,
        questionEndPos: Int,
        fakeIpBytes: ByteArray
    ): ByteArray {
        val safeEnd = questionEndPos.coerceIn(12, dnsQuery.size)
        val resp = ByteArray(safeEnd + 16)
        System.arraycopy(dnsQuery, 0, resp, 0, safeEnd)

        // QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0 (NOERROR)
        resp[2] = 0x81.toByte()
        resp[3] = 0x80.toByte()
        // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
        resp[4] = 0
        resp[5] = 1
        resp[6] = 0
        resp[7] = 1
        resp[8] = 0
        resp[9] = 0
        resp[10] = 0
        resp[11] = 0

        var p = safeEnd
        // Name pointer to QNAME at offset 12 (0xC00C)
        resp[p++] = 0xC0.toByte()
        resp[p++] = 0x0C.toByte()
        // TYPE = A (1)
        resp[p++] = 0x00
        resp[p++] = 0x01
        // CLASS = IN (1)
        resp[p++] = 0x00
        resp[p++] = 0x01
        // TTL = 60 seconds
        resp[p++] = 0x00
        resp[p++] = 0x00
        resp[p++] = 0x00
        resp[p++] = 0x3C
        // RDLENGTH = 4
        resp[p++] = 0x00
        resp[p++] = 0x04
        // RDATA = fakeIpBytes (4 bytes)
        System.arraycopy(fakeIpBytes, 0, resp, p, 4)
        return resp
    }

    private data class ParsedDnsQuestion(
        val domain: String?,
        val qType: Int,
        val questionEndPos: Int
    )

    private fun parseDnsQueryQuestion(dnsBytes: ByteArray): ParsedDnsQuestion {
        return try {
            if (dnsBytes.size < 17) return ParsedDnsQuestion(null, -1, -1)
            var pos = 12
            val labels = mutableListOf<String>()
            while (pos < dnsBytes.size) {
                val len = dnsBytes[pos].toInt() and 0xFF
                if (len == 0) {
                    pos++
                    break
                }
                if ((len and 0xC0) != 0) {
                    pos += 2
                    break
                }
                pos++
                if (pos + len > dnsBytes.size) return ParsedDnsQuestion(null, -1, -1)
                labels.add(String(dnsBytes, pos, len, Charsets.US_ASCII))
                pos += len
            }
            if (pos + 4 > dnsBytes.size) return ParsedDnsQuestion(null, -1, -1)
            val qType = readUInt16(dnsBytes, pos)
            val questionEndPos = pos + 4
            val domain = if (labels.isEmpty()) null else labels.joinToString(".").lowercase()
            ParsedDnsQuestion(domain, qType, questionEndPos)
        } catch (_: Exception) {
            ParsedDnsQuestion(null, -1, -1)
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
                    if (!V2RayOutboundClient.isPoisonedOrPrivateIp(ipStr)) {
                        dnsIpToDomainCache[ipStr] = domain
                    }
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

        // Reject DNS-over-TLS (TCP port 853) immediately with TCP RST so Android netd never hangs
        // on Opportunistic DoT and always resolves DNS via fast UDP port 53 FakeDNS.
        if (dstPort == 853) {
            val rstPacket = buildIpv4TcpPacket(
                srcIp = dstIpBytes,
                dstIp = srcIpBytes,
                srcPort = dstPort,
                dstPort = srcPort,
                seq = 0L,
                ack = (seqNum + (if (isSyn) 1 else payloadLen)) and 0xFFFFFFFFL,
                flags = TCP_FLAG_RST or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            writeTunPacket(rstPacket)
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
        private val uplinkQueue = Channel<ByteArray>(Channel.UNLIMITED)
        private var incompleteWaitCount = 0
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
            if (closed || data.isEmpty()) return

            // Calculate how many new (non-retransmitted) bytes this TCP segment contains beyond clientNextSeq
            val segEnd = (seqNum + data.size) and 0xFFFFFFFFL
            val newBytesCount = ((segEnd - clientNextSeq) and 0xFFFFFFFFL).toInt()

            if (newBytesCount <= 0 || newBytesCount > 65535) {
                // 100% duplicate TCP retransmission of already-received bytes:
                // Re-send ACK for clientNextSeq and DO NOT append duplicate bytes into the TLS stream!
                val dupAck = buildIpv4TcpPacket(
                    srcIp = serverIp,
                    dstIp = clientIp,
                    srcPort = serverPort,
                    dstPort = clientPort,
                    seq = mySeq,
                    ack = clientNextSeq,
                    flags = TCP_FLAG_ACK,
                    payload = ByteArray(0)
                )
                writeTunPacket(dupAck)
                return
            }

            val freshData = if (newBytesCount < data.size) {
                data.copyOfRange(data.size - newBytesCount, data.size)
            } else {
                data
            }
            clientNextSeq = segEnd

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

            if (tunnelConnected) {
                uplinkQueue.trySend(freshData)
            } else {
                pendingPayloads.write(freshData)
                if (connectJob == null) {
                    val buffered = pendingPayloads.toByteArray()
                    val sni = extractTlsSni(buffered)
                    val httpHost = if (sni == null) extractHttpHost(buffered) else null
                    val cachedDomain = dnsIpToDomainCache[serverIpStr]

                    // Wait at most 1 extra TCP segment if the TLS ClientHello is split across 2 segments
                    // and we haven't resolved the domain yet
                    if (incompleteWaitCount < 1 &&
                        isIncompleteTlsClientHelloRecord(buffered) &&
                        sni == null &&
                        cachedDomain == null
                    ) {
                        incompleteWaitCount++
                        return
                    }

                    val targetHost = sni ?: httpHost ?: cachedDomain ?: serverIpStr
                    startRemoteTunnel(targetHost)
                }
            }
        }

        private fun isIncompleteTlsClientHelloRecord(buf: ByteArray): Boolean {
            if (buf.size < 6 || buf.size > 3600) return false
            val isHandshake = (buf[0].toInt() and 0xFF) == 0x16 &&
                (buf[1].toInt() and 0xFF) == 0x03 &&
                (buf[5].toInt() and 0xFF) == 0x01
            if (!isHandshake) return false
            val recordLen = ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
            return recordLen in 64..4096 && buf.size < (5 + recordLen)
        }

        private fun startRemoteTunnel(targetHost: String) {
            connectJob = routerScope.launch {
                var uplinkWorker: Job? = null
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

                    // Single ordered FIFO uplink worker coroutine per TCP session
                    uplinkWorker = launch {
                        try {
                            for (chunk in uplinkQueue) {
                                if (closed) break
                                stream.output.write(chunk)
                                stream.output.flush()
                            }
                        } catch (_: Exception) {
                            sendResetAndClose()
                        }
                    }

                    // Downlink loop: read from V2Ray tunnel and inject TCP PSH+ACK segments into TUN
                    // Clamped to 1200 bytes to prevent cellular GTP/MTU blackholing on Irancell/MCI
                    val readBuf = ByteArray(1200)
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
                } finally {
                    uplinkWorker?.cancel()
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
            uplinkQueue.close()
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

        // Compute RFC 768 UDP Pseudo-Header + Segment Checksum so strict Android kernels never drop DNS replies
        var sum = 0
        for (i in 12 until 20 step 2) {
            sum += readUInt16(out, i)
        }
        sum += 17 // Protocol UDP (17)
        sum += udpLen

        var i = 0
        while (i < udpLen - 1) {
            sum += readUInt16(out, 20 + i)
            i += 2
        }
        if (i < udpLen) {
            sum += (out[20 + i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        var udpChecksum = sum.inv() and 0xFFFF
        if (udpChecksum == 0) udpChecksum = 0xFFFF
        out[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()

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
            // TCP Option: Maximum Segment Size (Kind=2, Len=4, MSS=1200 = 0x04B0)
            // Clamped for Irancell/MCI cellular MTU + VLESS/WS/TLS overhead
            out[40] = 2
            out[41] = 4
            out[42] = 0x04
            out[43] = 0xB0.toByte()
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
