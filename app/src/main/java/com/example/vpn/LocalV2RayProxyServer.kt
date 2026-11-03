package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Local multi-protocol proxy server supporting:
 * 1. Unbounded cached thread pool (`relayExecutor`) so `tun2socks` concurrent TCP/UDP sockets
 *    never hit Kotlin's 64-thread `Dispatchers.IO` starvation deadlock on Android.
 * 2. Real Tunnel DNS Resolution (`Android DNS -> TUN -> SOCKS5/V2Ray -> Remote DNS -> Real IP`):
 *    - Never fabricates counter-based or synthetic Fake IPs for X, Instagram/Meta, or any site.
 *    - Resolves `A` (`QTYPE=1`), `HTTPS/SVCB` (`QTYPE=65/64`), `CNAME`, etc. genuinely inside the
 *      encrypted V2Ray tunnel (`8.8.8.8:53` / `1.1.1.1:53` and DoH fallback).
 *    - Passively records real `A` record IPv4s (`realIpToDomain`) from unpoisoned DNS answers.
 *    - Suppresses only `AAAA` (`QTYPE=28`) while IPv6 is disabled on the TUN interface.
 * 3. Full TLS `ClientHello` Record Reassembly + Domain-First Outbound Routing (`destOverride: ["http", "tls"]`):
 *    - Reassembles multi-segment TLS 1.3 Post-Quantum `ClientHello` packets (`> 1240` bytes)
 *      before extracting the `SNI` hostname so VLESS/Trojan outbounds receive the real domain name
 *      while keeping the real DNS IPv4 as `fallbackIpv4`.
 * 4. Verified First-Response Multi-Server Failover + Concurrent Stream Load-Balancing:
 *    - Verifies that the remote V2Ray server actually connected to `targetHost:targetPort` and
 *      returned the first response bytes (`ServerHello`) before committing to that server.
 */
class LocalV2RayProxyServer(
  configs: List<V2RayConfig>,
  private val protector: (Socket) -> Boolean,
  private val udpProtector: (DatagramSocket) -> Boolean = { true },
) {
  constructor(
    config: V2RayConfig,
    protector: (Socket) -> Boolean,
    udpProtector: (DatagramSocket) -> Boolean = { true },
  ) : this(listOf(config), protector, udpProtector)

  companion object {
    private val realIpToDomain = ConcurrentHashMap<String, String>()

    /**
     * Passively records real IPv4 `A` records from an authentic DNS response so non-SNI connections
     * to a real resolved IPv4 can also know the domain name that resolved to it.
     */
    fun recordRealDnsARecords(domain: String, dnsBytes: ByteArray) {
      val cleanDomain = domain.trim().trimEnd('.').lowercase()
      if (cleanDomain.isEmpty() || dnsBytes.size < 12) return
      val qdCount = ((dnsBytes[4].toInt() and 0xFF) shl 8) or (dnsBytes[5].toInt() and 0xFF)
      val anCount = ((dnsBytes[6].toInt() and 0xFF) shl 8) or (dnsBytes[7].toInt() and 0xFF)
      if (anCount <= 0) return

      var offset = 12
      repeat(qdCount) {
        offset = skipDnsNameStatic(dnsBytes, offset)
        if (offset < 0 || offset + 4 > dnsBytes.size) return
        offset += 4
      }
      repeat(anCount) {
        offset = skipDnsNameStatic(dnsBytes, offset)
        if (offset < 0 || offset + 10 > dnsBytes.size) return
        val type = ((dnsBytes[offset].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 1].toInt() and 0xFF)
        val rdLen = ((dnsBytes[offset + 8].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 9].toInt() and 0xFF)
        offset += 10
        if (offset + rdLen > dnsBytes.size) return
        if (type == 1 && rdLen == 4) {
          val ipv4Bytes = dnsBytes.copyOfRange(offset, offset + 4)
          if (V2RayOutboundClient.isPublicRoutableIpv4(ipv4Bytes)) {
            val ipStr =
              "${ipv4Bytes[0].toInt() and 0xFF}.${ipv4Bytes[1].toInt() and 0xFF}.${ipv4Bytes[2].toInt() and 0xFF}.${ipv4Bytes[3].toInt() and 0xFF}"
            realIpToDomain[ipStr] = cleanDomain
          }
        }
        offset += rdLen
      }
    }

    fun lookupDomainForRealIp(hostOrIp: String): String? {
      return realIpToDomain[hostOrIp.trim()]
    }

    private fun skipDnsNameStatic(buf: ByteArray, startOffset: Int): Int {
      var offset = startOffset
      var jumps = 0
      while (offset < buf.size && jumps < 16) {
        val len = buf[offset].toInt() and 0xFF
        if (len == 0) return offset + 1
        if ((len and 0xC0) == 0xC0) return offset + 2
        offset += 1 + len
        jumps++
      }
      return -1
    }
  }

  private data class OpenedTunnelWithReply(
    val connection: V2RayOutboundClient.TunnelConnection,
    val firstReplyBytes: ByteArray?,
    val firstReplyLen: Int,
  )

  private val serverPool: List<V2RayConfig> =
    configs.ifEmpty {
      throw IllegalArgumentException("At least one V2RayConfig is required")
    }
  private val activeConfigIndex = AtomicInteger(0)
  private val streamDispatchCounter = AtomicInteger(0)
  private val penalizedIndices = ConcurrentHashMap.newKeySet<Int>()
  private val dnsCache = ConcurrentHashMap<String, ByteArray>()
  private val inFlightDnsLocks = ConcurrentHashMap<String, Any>()
  private val running = AtomicBoolean(false)

  private val relayExecutor: ExecutorService =
    Executors.newCachedThreadPool { runnable ->
      Thread(runnable, "meh-proxy-worker").apply {
        isDaemon = true
      }
    }

  private var serverSocket: ServerSocket? = null
  private var udpRelaySocket: DatagramSocket? = null

  var listenPort: Int = 0
    private set

  var udpListenPort: Int = 0
    private set

  val activeConfig: V2RayConfig
    get() = serverPool[activeConfigIndex.get().coerceIn(0, serverPool.lastIndex)]

  fun start(): Int {
    val localhost = InetAddress.getByName("127.0.0.1")
    val server = ServerSocket(0, 512, localhost)
    serverSocket = server
    listenPort = server.localPort

    val udpServer = DatagramSocket(0, localhost)
    udpRelaySocket = udpServer
    udpListenPort = udpServer.localPort
    running.set(true)

    relayExecutor.execute {
      while (running.get() && !server.isClosed) {
        try {
          val client = server.accept()
          client.tcpNoDelay = true
          client.soTimeout = 20_000
          relayExecutor.execute { handleClient(client) }
        } catch (_: Exception) {
          if (server.isClosed || !running.get()) break
        }
      }
    }

    relayExecutor.execute {
      val buf = ByteArray(4096)
      while (running.get() && !udpServer.isClosed) {
        try {
          val pkt = DatagramPacket(buf, buf.size)
          udpServer.receive(pkt)
          val dataCopy = buf.copyOfRange(0, pkt.length)
          val clientAddr = pkt.address
          val clientPort = pkt.port
          relayExecutor.execute {
            handleSocks5UdpDatagram(udpServer, dataCopy, clientAddr, clientPort)
          }
        } catch (_: Exception) {
          if (udpServer.isClosed || !running.get()) break
        }
      }
    }

    return listenPort
  }

  fun stop() {
    running.set(false)
    try {
      serverSocket?.close()
    } catch (_: Exception) {}
    try {
      udpRelaySocket?.close()
    } catch (_: Exception) {}
    serverSocket = null
    udpRelaySocket = null
    dnsCache.clear()
    inFlightDnsLocks.clear()
    penalizedIndices.clear()
    try {
      relayExecutor.shutdownNow()
    } catch (_: Exception) {}
  }

  /**
   * Opens a V2Ray tunnel across `serverPool` with:
   * 1. Load distribution across healthy verified servers when apps (Instagram/Twitter) burst
   *    15–30 parallel connections, avoiding single-Cloudflare-Worker 6-connection throttling.
   * 2. End-to-end first-response verification (`awaitFirstResponse = true`): when the client sends
   *    an initial TLS `ClientHello` or HTTP request, we verify that the V2Ray server actually
   *    connected to `targetHost:targetPort` and returned at least 1 response byte (`ServerHello`).
   * 3. Dual-target fallback (`fallbackIpv4`): if a candidate server fails to connect using the
   *    domain name `targetHost` (e.g. a Cloudflare Worker with restricted DNS), we also try
   *    connecting via the clean public IPv4 `fallbackIpv4` before failing over to the next server!
   */
  private fun openTunnelWithVerifiedFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 5000,
    initialPayload: ByteArray? = null,
    initialPayloadLen: Int = 0,
    awaitFirstResponse: Boolean = false,
    fallbackIpv4: String? = null,
  ): OpenedTunnelWithReply {
    val poolSize = serverPool.size
    val healthyIndices = (0 until poolSize).filter { it !in penalizedIndices }
    val activeWindow = if (healthyIndices.isNotEmpty()) healthyIndices else (0 until poolSize).toList()
    val windowSize = minOf(activeWindow.size, 4)

    val startSlot =
      if (windowSize > 1 && initialPayloadLen > 0) {
        (streamDispatchCounter.getAndIncrement() and 0x7FFFFFFF) % windowSize
      } else {
        0
      }

    // Order candidate indices: first the healthy window starting at startSlot, then remaining pool
    val orderedIndices = ArrayList<Int>(poolSize)
    for (i in activeWindow.indices) {
      orderedIndices.add(activeWindow[(startSlot + i) % activeWindow.size])
    }
    for (idx in 0 until poolSize) {
      if (idx !in orderedIndices) {
        orderedIndices.add(idx)
      }
    }

    val targetsToTry =
      if (!fallbackIpv4.isNullOrBlank() &&
        fallbackIpv4 != targetHost &&
        V2RayOutboundClient.parseIpv4Bytes(fallbackIpv4)?.let { V2RayOutboundClient.isPublicRoutableIpv4(it) } == true
      ) {
        listOf(targetHost, fallbackIpv4)
      } else {
        listOf(targetHost)
      }

    var lastError: Exception? = null

    for ((attemptIdx, idx) in orderedIndices.withIndex()) {
      val candidate = serverPool[idx]
      for (hostCandidate in targetsToTry) {
        var conn: V2RayOutboundClient.TunnelConnection? = null
        try {
          val connectTimeout = if (attemptIdx == 0) timeoutMs else 3800
          conn =
            V2RayOutboundClient.openTunnel(
              config = candidate,
              targetHost = hostCandidate,
              targetPort = targetPort,
              timeoutMs = connectTimeout,
              protector = protector,
            )
          if (initialPayload != null && initialPayloadLen > 0) {
            conn.outputStream.write(initialPayload, 0, initialPayloadLen)
            conn.outputStream.flush()

            if (awaitFirstResponse) {
              conn.setReadTimeout(4000)
              val replyBuf = ByteArray(16384)
              val replyLen = conn.inputStream.read(replyBuf)
              if (replyLen <= 0) {
                throw IOException("V2Ray server ${candidate.address} closed stream before replying for $hostCandidate:$targetPort")
              }
              conn.setReadTimeout(60_000)
              penalizedIndices.remove(idx)
              activeConfigIndex.set(idx)
              return OpenedTunnelWithReply(conn, replyBuf, replyLen)
            }
          }
          conn.setReadTimeout(60_000)
          return OpenedTunnelWithReply(conn, null, 0)
        } catch (e: Exception) {
          try {
            conn?.close()
          } catch (_: Exception) {}
          lastError = e
        }
      }
      // If this candidate failed for all host targets, mark it penalized so burst streams prefer working nodes
      if (poolSize > 1) {
        penalizedIndices.add(idx)
      }
    }
    throw lastError ?: IOException("All V2Ray servers in pool failed for $targetHost:$targetPort")
  }

  private fun handleClient(clientSocket: Socket) {
    try {
      clientSocket.use { client ->
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        val firstByte = clientIn.read()
        if (firstByte == -1) return

        if (firstByte == 0x05) {
          handleSocks5Client(client, clientIn, clientOut)
        } else {
          handleHttpProxyClient(client, firstByte.toByte(), clientIn, clientOut)
        }
      }
    } catch (_: Exception) {}
  }

  /**
   * Reads the initial client payload from [clientIn]. If the payload starts with a valid TLS
   * Handshake record (`0x16, 0x03, 0x01..0x04`), reassembles the complete TLS record (`5 + recordLen`
   * bytes) across TCP segments so large Post-Quantum TLS 1.3 `ClientHello` packets (used by Twitter/X
   * and Instagram) always include their `SNI` extension even when split by the 1400-byte TUN MTU.
   */
  private fun readCompleteFirstClientPacket(
    clientSocket: Socket,
    clientIn: InputStream,
    buffer: ByteArray,
  ): Int {
    var totalRead =
      try {
        clientSocket.soTimeout = 3000
        val n = clientIn.read(buffer)
        if (n <= 0) return n
        n
      } catch (_: SocketTimeoutException) {
        return 0
      }

    if (totalRead >= 3 &&
      (buffer[0].toInt() and 0xFF) == 0x16 &&
      (buffer[1].toInt() and 0xFF) == 0x03 &&
      (buffer[2].toInt() and 0xFF) in 1..4
    ) {
      try {
        clientSocket.soTimeout = 600
        while (totalRead < 5) {
          val r = clientIn.read(buffer, totalRead, 5 - totalRead)
          if (r <= 0) break
          totalRead += r
        }
        if (totalRead >= 5) {
          val recordPayloadLen =
            ((buffer[3].toInt() and 0xFF) shl 8) or (buffer[4].toInt() and 0xFF)
          if (recordPayloadLen in 1..16384) {
            val expectedTotal = (5 + recordPayloadLen).coerceAtMost(buffer.size)
            while (totalRead < expectedTotal) {
              // If we already have the complete SNI extension, don't block if no more bytes are immediately queued
              val r = clientIn.read(buffer, totalRead, expectedTotal - totalRead)
              if (r <= 0) break
              totalRead += r
            }
          }
        }
      } catch (_: SocketTimeoutException) {
        // Proceed with bytes read so far
      }
    }
    return totalRead
  }

  /**
   * Handles RFC 1035 DNS-over-TCP (`[2-byte length][dnsQuery]`) locally via `resolveDnsOverV2Ray`.
   */
  private fun handleLocalTcpDnsSession(
    clientSocket: Socket,
    clientIn: InputStream,
    clientOut: OutputStream,
  ) {
    clientSocket.soTimeout = 6000
    val lenBuf = ByteArray(2)
    while (running.get()) {
      if (!readExact(clientIn, lenBuf)) break
      val queryLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
      if (queryLen !in 12..4096) break
      val queryBytes = ByteArray(queryLen)
      if (!readExact(clientIn, queryBytes)) break
      val respBytes = resolveDnsOverV2Ray(queryBytes) ?: break
      val outFrame = ByteArray(2 + respBytes.size)
      outFrame[0] = ((respBytes.size ushr 8) and 0xFF).toByte()
      outFrame[1] = (respBytes.size and 0xFF).toByte()
      System.arraycopy(respBytes, 0, outFrame, 2, respBytes.size)
      clientOut.write(outFrame)
      clientOut.flush()
    }
  }

  private fun handleSocks5Client(
    clientSocket: Socket,
    clientIn: InputStream,
    clientOut: OutputStream,
  ) {
    val nMethods = clientIn.read()
    if (nMethods < 0) return
    val methods = ByteArray(nMethods)
    if (!readExact(clientIn, methods)) return

    // Reply: SOCKS5, NO AUTH (0x00)
    clientOut.write(byteArrayOf(0x05, 0x00))
    clientOut.flush()

    val reqHeader = ByteArray(4)
    if (!readExact(clientIn, reqHeader)) return
    val cmd = reqHeader[1].toInt() and 0xFF
    val atyp = reqHeader[3].toInt() and 0xFF

    val rawTargetHost: String =
      when (atyp) {
        0x01 -> {
          val ipv4 = ByteArray(4)
          if (!readExact(clientIn, ipv4)) return
          "${ipv4[0].toInt() and 0xFF}.${ipv4[1].toInt() and 0xFF}.${ipv4[2].toInt() and 0xFF}.${ipv4[3].toInt() and 0xFF}"
        }
        0x03 -> {
          val len = clientIn.read()
          if (len <= 0) return
          val domain = ByteArray(len)
          if (!readExact(clientIn, domain)) return
          String(domain, Charsets.UTF_8)
        }
        0x04 -> {
          val ipv6 = ByteArray(16)
          if (!readExact(clientIn, ipv6)) return
          InetAddress.getByAddress(ipv6).hostAddress ?: return
        }
        else -> return
      }

    val portBytes = ByteArray(2)
    if (!readExact(clientIn, portBytes)) return
    val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

    when (cmd) {
      0x01 -> {
        // Intercept TCP port 53 (DNS-over-TCP) and answer locally via `resolveDnsOverV2Ray`
        if (targetPort == 53) {
          clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
          clientOut.flush()
          handleLocalTcpDnsSession(clientSocket, clientIn, clientOut)
          return
        }

        var effectiveHost = rawTargetHost

        // Acknowledge SOCKS5 CONNECT so the client immediately sends its first packet
        // (TLS ClientHello / HTTP request / MTProto preamble / DoT port 853 handshake)
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
        clientOut.flush()

        val firstBuffer = ByteArray(32768)
        val firstLen = readCompleteFirstClientPacket(clientSocket, clientIn, firstBuffer)
        if (firstLen == -1) return

        // Domain-first routing (`destOverride: ["http", "tls"]`):
        // Whenever the packet is a TLS ClientHello with an SNI hostname or an HTTP request with a
        // Host header, pass the exact sniffed domain name to the VLESS/Trojan outbound so the remote
        // V2Ray server resolves it directly, while keeping the real DNS IPv4 `rawTargetHost` as fallback!
        var isHttpOrTlsRequest = false
        if (firstLen > 0) {
          val tlsSni = GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
          val httpHost = if (tlsSni == null) extractHttpHostHeader(firstBuffer, firstLen) else null
          val sniffedDomain = tlsSni ?: httpHost
          if (!sniffedDomain.isNullOrBlank()) {
            effectiveHost = sniffedDomain
            isHttpOrTlsRequest = true
          } else if ((firstBuffer[0].toInt() and 0xFF) == 0x16) {
            isHttpOrTlsRequest = true
          }
        }

        // Reject un-sniffed ISP-poisoned 10.x.x.x IPs or un-sniffed raw IPv6 addresses immediately
        val ipv4Target = V2RayOutboundClient.parseIpv4Bytes(effectiveHost)
        if (ipv4Target != null && (ipv4Target[0].toInt() and 0xFF) == 10) {
          return
        }
        if (effectiveHost.contains(':')) {
          return
        }

        clientSocket.soTimeout = 0

        val opened =
          try {
            openTunnelWithVerifiedFailover(
              targetHost = effectiveHost,
              targetPort = targetPort,
              initialPayload = firstBuffer,
              initialPayloadLen = firstLen,
              awaitFirstResponse = isHttpOrTlsRequest && firstLen > 0,
              fallbackIpv4 = rawTargetHost,
            )
          } catch (_: Exception) {
            return
          }

        opened.connection.use { activeTunnel ->
          if (opened.firstReplyBytes != null && opened.firstReplyLen > 0) {
            clientOut.write(opened.firstReplyBytes, 0, opened.firstReplyLen)
            clientOut.flush()
          }
          relayStreams(
            clientIn = clientIn,
            clientOut = clientOut,
            remoteIn = activeTunnel.inputStream,
            remoteOut = activeTunnel.outputStream,
            clientSocket = clientSocket,
            tunnelConnection = activeTunnel,
          )
        }
      }
      0x03 -> {
        // UDP ASSOCIATE: keep control socket open for the entire lifetime of the tun2socks session
        // (soTimeout = 0) so UDP DNS associations never expire while browsing!
        clientSocket.soTimeout = 0
        val pHigh = ((udpListenPort ushr 8) and 0xFF).toByte()
        val pLow = (udpListenPort and 0xFF).toByte()
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pHigh, pLow))
        clientOut.flush()
        try {
          while (running.get() && clientIn.read() != -1) {
            // Wait until client closes TCP control connection
          }
        } catch (_: Exception) {}
      }
      else -> {
        clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        clientOut.flush()
      }
    }
  }

  /**
   * Extracts the `Host:` domain name from an HTTP/1.1 request if `buf` starts with an HTTP verb.
   */
  private fun extractHttpHostHeader(buf: ByteArray, len: Int): String? {
    if (len < 16) return null
    val b0 = buf[0].toInt().toChar()
    if (b0 != 'G' && b0 != 'P' && b0 != 'H' && b0 != 'O' && b0 != 'D' && b0 != 'C') return null
    val sampleLen = minOf(len, 2048)
    val text = String(buf, 0, sampleLen, Charsets.ISO_8859_1)
    if (!text.startsWith("GET ") &&
      !text.startsWith("POST ") &&
      !text.startsWith("HEAD ") &&
      !text.startsWith("PUT ") &&
      !text.startsWith("DELETE ") &&
      !text.startsWith("OPTIONS ")
    ) {
      return null
    }
    for (line in text.lineSequence()) {
      if (line.isEmpty()) break
      if (line.startsWith("Host:", ignoreCase = true)) {
        val hostVal =
          line
            .substringAfter(":")
            .trim()
            .substringBefore(":")
            .trim()
            .trimEnd('.')
            .lowercase()
        if (hostVal.contains('.') && V2RayOutboundClient.parseIpv4Bytes(hostVal) == null) {
          return hostVal
        }
      }
    }
    return null
  }

  /**
   * Handles a SOCKS5 UDP datagram from tun2socks:
   * Header: [RSV(2), FRAG(1), ATYP(1), DST.ADDR(var), DST.PORT(2), DATA...]
   */
  private fun handleSocks5UdpDatagram(
    udpServer: DatagramSocket,
    packet: ByteArray,
    clientAddr: InetAddress,
    clientPort: Int,
  ) {
    if (packet.size < 10) return
    val frag = packet[2].toInt() and 0xFF
    if (frag != 0) return
    val atyp = packet[3].toInt() and 0xFF

    var offset = 4
    when (atyp) {
      0x01 -> {
        if (packet.size < offset + 6) return
        offset += 4
      }
      0x03 -> {
        val len = packet[offset].toInt() and 0xFF
        offset += 1
        if (packet.size < offset + len + 2) return
        offset += len
      }
      0x04 -> {
        if (packet.size < offset + 18) return
        offset += 16
      }
      else -> return
    }

    val dstPort = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    offset += 2

    // Drop non-DNS UDP packets (such as UDP port 443 QUIC/HTTP3) so apps immediately
    // fall back to TCP port 443 over the encrypted V2Ray tunnel instead of leaking over ISP UDP.
    if (dstPort != 53) return

    val socksUdpHeader = packet.copyOfRange(0, offset)
    val udpPayload = packet.copyOfRange(offset, packet.size)
    if (udpPayload.size < 12) return

    val responsePayload = resolveDnsOverV2Ray(udpPayload) ?: return

    val replyBytes = ByteArray(socksUdpHeader.size + responsePayload.size)
    System.arraycopy(socksUdpHeader, 0, replyBytes, 0, socksUdpHeader.size)
    System.arraycopy(responsePayload, 0, replyBytes, socksUdpHeader.size, responsePayload.size)

    try {
      udpServer.send(DatagramPacket(replyBytes, replyBytes.size, clientAddr, clientPort))
    } catch (_: Exception) {}
  }

  private data class DnsQuestion(
    val domain: String,
    val qtype: Int,
    val qclass: Int,
    val questionEndOffset: Int,
  )

  private fun parseDnsQuestion(dnsQuery: ByteArray): DnsQuestion? {
    if (dnsQuery.size < 17) return null
    var offset = 12
    val sb = StringBuilder()
    while (offset < dnsQuery.size) {
      val len = dnsQuery[offset].toInt() and 0xFF
      offset += 1
      if (len == 0) break
      if (len >= 0xC0 || offset + len > dnsQuery.size) return null
      if (sb.isNotEmpty()) sb.append('.')
      sb.append(String(dnsQuery, offset, len, Charsets.US_ASCII).lowercase())
      offset += len
    }
    if (offset + 4 > dnsQuery.size) return null
    val qtype = ((dnsQuery[offset].toInt() and 0xFF) shl 8) or (dnsQuery[offset + 1].toInt() and 0xFF)
    val qclass = ((dnsQuery[offset + 2].toInt() and 0xFF) shl 8) or (dnsQuery[offset + 3].toInt() and 0xFF)
    return DnsQuestion(
      domain = sb.toString(),
      qtype = qtype,
      qclass = qclass,
      questionEndOffset = offset + 4,
    )
  }

  /**
   * Resolves DNS queries genuinely over the V2Ray tunnel (`Android DNS -> TUN -> SOCKS5/V2Ray -> Remote DNS`):
   * 1. Suppresses only `AAAA` (`QTYPE=28`) while IPv6 is disabled on the TUN interface.
   *    Does NOT suppress `HTTPS/SVCB` (`QTYPE=65/64`) so modern clients (Chromium/Cronet, Instagram, X)
   *    receive authentic `HTTPS/SVCB` and `A` records from the upstream DNS server.
   * 2. Uses `dnsCache` + in-flight deduplication (`inFlightDnsLocks`) and records real `A` records
   *    into `realIpToDomain` without ever fabricating Fake IPs.
   * 3. Resolves via 1-RTT RFC 1035 DNS-over-TCP (`8.8.8.8:53` / `1.1.1.1:53`) inside the V2Ray tunnel,
   *    with DoH over the V2Ray tunnel (`8.8.8.8:443` / `1.1.1.1:443`) as fallback.
   */
  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.size < 12) return null
    val question = parseDnsQuestion(dnsQuery)
    if (question != null) {
      // Only suppress IPv6 AAAA (QTYPE=28) because the TUN interface is IPv4-only.
      // HTTPS/SVCB (QTYPE=65/64) and A (QTYPE=1) are resolved genuinely through the tunnel.
      if (question.qtype == 28) {
        return buildEmptyDnsNoerrorResponse(dnsQuery, question.questionEndOffset)
      }
    }

    val cacheKey =
      if (question != null) {
        "${question.domain}:${question.qtype}:${question.qclass}"
      } else {
        null
      }

    if (cacheKey != null) {
      dnsCache[cacheKey]?.let { cached ->
        if (cached.size >= 12) {
          val copy = cached.copyOf()
          copy[0] = dnsQuery[0]
          copy[1] = dnsQuery[1]
          return copy
        }
      }
    }

    val lock = if (cacheKey != null) inFlightDnsLocks.computeIfAbsent(cacheKey) { Any() } else Any()
    synchronized(lock) {
      try {
        if (cacheKey != null) {
          dnsCache[cacheKey]?.let { cached ->
            if (cached.size >= 12) {
              val copy = cached.copyOf()
              copy[0] = dnsQuery[0]
              copy[1] = dnsQuery[1]
              return copy
            }
          }
        }

        // 1. When running in Serverless mode, resolve real IPs via fragmented DoH (port 443)
        if (activeConfig.protocol == V2RayProtocol.SERVERLESS) {
          val directDoh = resolveDnsOverHttpsProtectedDirect(dnsQuery)
          if (directDoh != null && isValidUnpoisonedDnsResponse(directDoh)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, directDoh)
            }
            if (cacheKey != null && dnsCache.size < 1024) {
              dnsCache[cacheKey] = directDoh.copyOf()
            }
            return directDoh
          }
        } else {
          // 2. Primary: Fast 1-RTT DNS-over-TCP (`8.8.8.8:53` / `1.1.1.1:53`) inside the V2Ray tunnel
          val tcpDnsResp = resolveDnsOverTcpViaTunnel(dnsQuery)
          if (tcpDnsResp != null && isValidUnpoisonedDnsResponse(tcpDnsResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, tcpDnsResp)
            }
            if (cacheKey != null && dnsCache.size < 1024) {
              dnsCache[cacheKey] = tcpDnsResp.copyOf()
            }
            return tcpDnsResp
          }

          // 3. Secondary: DNS-over-HTTPS (`8.8.8.8:443` / `1.1.1.1:443`) inside the V2Ray tunnel
          val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery)
          if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, dohTunnelResp)
            }
            if (cacheKey != null && dnsCache.size < 1024) {
              dnsCache[cacheKey] = dohTunnelResp.copyOf()
            }
            return dohTunnelResp
          }
        }

        // 4. Last-resort fallback: Protected direct fragmented DoH (`8.8.8.8:443` / `1.1.1.1:443`)
        val directDohResp = resolveDnsOverHttpsProtectedDirect(dnsQuery)
        if (directDohResp != null && isValidUnpoisonedDnsResponse(directDohResp)) {
          if (question != null) {
            recordRealDnsARecords(question.domain, directDohResp)
          }
          if (cacheKey != null && dnsCache.size < 1024) {
            dnsCache[cacheKey] = directDohResp.copyOf()
          }
          return directDohResp
        }
      } finally {
        if (cacheKey != null) {
          inFlightDnsLocks.remove(cacheKey, lock)
        }
      }
    }

    // Never return a synthetic FakeIP; return a clean RFC 1035 SERVFAIL (RCODE=2) so Android retries cleanly
    return buildDnsServfailResponse(dnsQuery, question?.questionEndOffset ?: dnsQuery.size)
  }

  /**
   * Resolves [dnsQuery] using RFC 1035 DNS-over-TCP (`[2-byte length][dnsQuery]`) to `8.8.8.8:53`
   * or `1.1.1.1:53` over the V2Ray tunnel in a single round-trip (zero inner TLS handshake).
   */
  private fun resolveDnsOverTcpViaTunnel(dnsQuery: ByteArray): ByteArray? {
    val tcpFrame = ByteArray(2 + dnsQuery.size)
    tcpFrame[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
    tcpFrame[1] = (dnsQuery.size and 0xFF).toByte()
    System.arraycopy(dnsQuery, 0, tcpFrame, 2, dnsQuery.size)

    for (dnsServerIp in listOf("8.8.8.8", "1.1.1.1")) {
      try {
        val opened =
          openTunnelWithVerifiedFailover(
            targetHost = dnsServerIp,
            targetPort = 53,
            timeoutMs = 2200,
            initialPayload = tcpFrame,
            initialPayloadLen = tcpFrame.size,
            awaitFirstResponse = true,
          )
        opened.connection.use { tunnel ->
          val firstBytes = opened.firstReplyBytes ?: return@use
          val firstLen = opened.firstReplyLen
          if (firstLen <= 0) return@use

          val buf = ByteArrayOutputStream(512)
          buf.write(firstBytes, 0, firstLen)
          val tmp = ByteArray(512)

          while (buf.size() < 2) {
            val r = tunnel.inputStream.read(tmp)
            if (r <= 0) break
            buf.write(tmp, 0, r)
          }
          val current = buf.toByteArray()
          if (current.size < 2) return@use
          val expectedDnsLen = ((current[0].toInt() and 0xFF) shl 8) or (current[1].toInt() and 0xFF)
          if (expectedDnsLen !in 12..4096) return@use

          while (buf.size() < 2 + expectedDnsLen) {
            val r = tunnel.inputStream.read(tmp)
            if (r <= 0) break
            buf.write(tmp, 0, r)
          }
          val full = buf.toByteArray()
          if (full.size >= 2 + expectedDnsLen) {
            val dnsResp = full.copyOfRange(2, 2 + expectedDnsLen)
            dnsResp[0] = dnsQuery[0]
            dnsResp[1] = dnsQuery[1]
            return dnsResp
          }
        }
      } catch (_: Exception) {}
    }
    return null
  }

  private fun resolveDnsOverHttpsViaTunnel(dnsQuery: ByteArray): ByteArray? {
    for ((targetIp, sniHost) in listOf("8.8.8.8" to "dns.google", "1.1.1.1" to "cloudflare-dns.com")) {
      try {
        val opened =
          openTunnelWithVerifiedFailover(
            targetHost = targetIp,
            targetPort = 443,
            timeoutMs = 2500,
          )
        opened.connection.use { tunnel ->
          val (tlsIn, tlsOut) =
            GfwKnockerXrayCore.openSslEngineOverStreams(
              sslContext = V2RayOutboundClient.permissiveSslContext,
              rawIn = tunnel.inputStream,
              rawOut = tunnel.outputStream,
              sniHost = sniHost,
              port = 443,
            )
          val resp = executeDohPost(tlsIn, tlsOut, sniHost, dnsQuery)
          if (resp != null) return resp
        }
      } catch (_: Exception) {}
    }
    return null
  }

  private fun resolveDnsOverHttpsProtectedDirect(dnsQuery: ByteArray): ByteArray? {
    val dohTargets =
      listOf(
        Triple(byteArrayOf(8, 8, 8, 8), "dns.google", "dns.google"),
        Triple(byteArrayOf(188.toByte(), 114, 98, 0), "challenges.cloudflare.com", "cloudflare-dns.com"),
        Triple(byteArrayOf(1, 1, 1, 1), "cloudflare-dns.com", "cloudflare-dns.com"),
      )
    val fragConfig =
      if (activeConfig.fragmentProfile.isBlank() || activeConfig.fragmentProfile == "direct_tls") {
        GfwKnockerXrayCore.FragmentConfig.AETHER_SNI_SPLIT
      } else {
        GfwKnockerXrayCore.FragmentConfig.fromProfileId(activeConfig.fragmentProfile)
      }
    for ((dohIp, sniHost, hostHdr) in dohTargets) {
      try {
        Socket().use { raw ->
          try {
            raw.reuseAddress
          } catch (_: Exception) {}
          protector(raw)
          raw.tcpNoDelay = true
          raw.soTimeout = 2200
          raw.connect(InetSocketAddress(InetAddress.getByAddress(dohIp), 443), 2200)
          val fragOut =
            GfwKnockerXrayCore.FragmentWriterOutputStream(
              raw.getOutputStream(),
              fragConfig,
            )
          val (tlsIn, tlsOut) =
            GfwKnockerXrayCore.openSslEngineOverStreams(
              sslContext = V2RayOutboundClient.permissiveSslContext,
              rawIn = raw.getInputStream(),
              rawOut = fragOut,
              sniHost = sniHost,
              port = 443,
            )
          val resp = executeDohPost(tlsIn, tlsOut, hostHdr, dnsQuery)
          if (resp != null) return resp
        }
      } catch (_: Exception) {}
    }
    return null
  }

  private fun executeDohPost(
    input: InputStream,
    output: OutputStream,
    hostHeader: String,
    dnsQuery: ByteArray,
  ): ByteArray? {
    val reqHeader =
      "POST /dns-query HTTP/1.1\r\n" +
        "Host: $hostHeader\r\n" +
        "Content-Type: application/dns-message\r\n" +
        "Accept: application/dns-message\r\n" +
        "Content-Length: ${dnsQuery.size}\r\n" +
        "Connection: close\r\n\r\n"
    output.write(reqHeader.toByteArray(Charsets.US_ASCII))
    output.write(dnsQuery)
    output.flush()

    val rawResp = ByteArrayOutputStream(1024)
    val buf = ByteArray(1024)
    while (rawResp.size() < 8192) {
      val n = input.read(buf)
      if (n <= 0) break
      rawResp.write(buf, 0, n)
    }
    val allBytes = rawResp.toByteArray()
    val headerStr = String(allBytes, Charsets.ISO_8859_1)
    if (!headerStr.startsWith("HTTP/1.1 200") && !headerStr.startsWith("HTTP/1.0 200")) {
      return null
    }
    val splitIdx = headerStr.indexOf("\r\n\r\n")
    if (splitIdx <= 0) return null
    val bodyOffset = splitIdx + 4
    if (allBytes.size - bodyOffset < 12) return null
    val contentLength =
      Regex("Content-Length:\\s*(\\d+)", RegexOption.IGNORE_CASE)
        .find(headerStr.substring(0, splitIdx))
        ?.groupValues
        ?.getOrNull(1)
        ?.toIntOrNull()
    return if (contentLength != null && bodyOffset + contentLength <= allBytes.size) {
      allBytes.copyOfRange(bodyOffset, bodyOffset + contentLength)
    } else {
      allBytes.copyOfRange(bodyOffset, allBytes.size)
    }
  }

  private fun isValidUnpoisonedDnsResponse(dnsBytes: ByteArray): Boolean {
    if (dnsBytes.size < 12) return false
    val qdCount = ((dnsBytes[4].toInt() and 0xFF) shl 8) or (dnsBytes[5].toInt() and 0xFF)
    val anCount = ((dnsBytes[6].toInt() and 0xFF) shl 8) or (dnsBytes[7].toInt() and 0xFF)
    var offset = 12
    repeat(qdCount) {
      offset = skipDnsName(dnsBytes, offset)
      if (offset < 0 || offset + 4 > dnsBytes.size) return false
      offset += 4
    }
    repeat(anCount) {
      offset = skipDnsName(dnsBytes, offset)
      if (offset < 0 || offset + 10 > dnsBytes.size) return true
      val type = ((dnsBytes[offset].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 1].toInt() and 0xFF)
      val rdLen = ((dnsBytes[offset + 8].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 9].toInt() and 0xFF)
      offset += 10
      if (offset + rdLen > dnsBytes.size) return true
      if (type == 1 && rdLen == 4) {
        val b0 = dnsBytes[offset].toInt() and 0xFF
        if (b0 == 10 || b0 == 127 || b0 == 0) {
          return false
        }
      }
      offset += rdLen
    }
    return true
  }

  private fun skipDnsName(buf: ByteArray, startOffset: Int): Int {
    var offset = startOffset
    var jumps = 0
    while (offset < buf.size && jumps < 16) {
      val len = buf[offset].toInt() and 0xFF
      if (len == 0) return offset + 1
      if ((len and 0xC0) == 0xC0) return offset + 2
      offset += 1 + len
      jumps++
    }
    return -1
  }

  private fun handleHttpProxyClient(
    clientSocket: Socket,
    firstByte: Byte,
    clientIn: InputStream,
    clientOut: OutputStream,
  ) {
    val headerBuf = ByteArrayOutputStream(512)
    headerBuf.write(firstByte.toInt())
    var state = 0
    while (headerBuf.size() < 16384) {
      val b = clientIn.read()
      if (b == -1) return
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

    val rawHeaders = headerBuf.toByteArray()
    val headerStr = String(rawHeaders, Charsets.ISO_8859_1)
    val firstLine = headerStr.lineSequence().firstOrNull().orEmpty().trim()
    val parts = firstLine.split(" ")
    if (parts.size < 2) return

    val method = parts[0].uppercase()
    val target = parts[1]

    if (method == "CONNECT") {
      val rawHost = target.substringBeforeLast(":").trim()
      val host = lookupDomainForRealIp(rawHost) ?: rawHost
      val port = target.substringAfterLast(":", "443").toIntOrNull() ?: 443
      if (host.isEmpty()) return

      val established = "HTTP/1.1 200 Connection Established\r\n\r\n"
      clientOut.write(established.toByteArray(Charsets.US_ASCII))
      clientOut.flush()

      val firstBuffer = ByteArray(32768)
      val firstLen = readCompleteFirstClientPacket(clientSocket, clientIn, firstBuffer)
      if (firstLen == -1) return

      var effectiveHost = host
      if (firstLen > 0) {
        val sniffed = GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
        if (!sniffed.isNullOrBlank()) {
          effectiveHost = sniffed
        }
      }
      clientSocket.soTimeout = 0

      val opened =
        openTunnelWithVerifiedFailover(
          targetHost = effectiveHost,
          targetPort = port,
          initialPayload = firstBuffer,
          initialPayloadLen = firstLen,
          awaitFirstResponse = firstLen > 0,
          fallbackIpv4 = rawHost,
        )
      opened.connection.use { tunnel ->
        if (opened.firstReplyBytes != null && opened.firstReplyLen > 0) {
          clientOut.write(opened.firstReplyBytes, 0, opened.firstReplyLen)
          clientOut.flush()
        }
        relayStreams(
          clientIn = clientIn,
          clientOut = clientOut,
          remoteIn = tunnel.inputStream,
          remoteOut = tunnel.outputStream,
          clientSocket = clientSocket,
          tunnelConnection = tunnel,
        )
      }
    } else {
      val withoutHttp = target.removePrefix("http://").removePrefix("https://")
      val authority = withoutHttp.substringBefore("/")
      val path = "/" + withoutHttp.substringAfter("/", "")
      val rawHost = authority.substringBeforeLast(":").trim()
      val host = lookupDomainForRealIp(rawHost) ?: rawHost
      val port =
        if (authority.contains(":")) {
          authority.substringAfterLast(":").toIntOrNull() ?: 80
        } else {
          80
        }
      if (host.isEmpty()) return

      val rewrittenHeader =
        headerStr.replaceFirst("$method $target ", "$method $path ")
      val rewrittenBytes = rewrittenHeader.toByteArray(Charsets.ISO_8859_1)
      clientSocket.soTimeout = 0

      val opened =
        openTunnelWithVerifiedFailover(
          targetHost = host,
          targetPort = port,
          initialPayload = rewrittenBytes,
          initialPayloadLen = rewrittenBytes.size,
          awaitFirstResponse = true,
          fallbackIpv4 = rawHost,
        )
      opened.connection.use { tunnel ->
        if (opened.firstReplyBytes != null && opened.firstReplyLen > 0) {
          clientOut.write(opened.firstReplyBytes, 0, opened.firstReplyLen)
          clientOut.flush()
        }
        relayStreams(
          clientIn = clientIn,
          clientOut = clientOut,
          remoteIn = tunnel.inputStream,
          remoteOut = tunnel.outputStream,
          clientSocket = clientSocket,
          tunnelConnection = tunnel,
        )
      }
    }
  }

  /**
   * Builds an RFC 1035 empty `NOERROR` response truncated to [questionEndOffset] (`QDCOUNT=1`,
   * `ANCOUNT=0`, `NSCOUNT=0`, `ARCOUNT=0`) so no trailing EDNS0 `OPT` bytes remain and Android's
   * `ns_initparse` (`cp == eom`) always accepts it.
   */
  private fun buildEmptyDnsNoerrorResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int = parseDnsQuestion(dnsQuery)?.questionEndOffset ?: dnsQuery.size,
  ): ByteArray {
    val safeLen = questionEndOffset.coerceIn(12, dnsQuery.size)
    val resp = dnsQuery.copyOfRange(0, safeLen)
    resp[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    resp[3] = 0x80.toByte()
    resp[4] = 0x00
    resp[5] = 0x01
    resp[6] = 0x00
    resp[7] = 0x00
    resp[8] = 0x00
    resp[9] = 0x00
    resp[10] = 0x00
    resp[11] = 0x00
    return resp
  }

  private fun buildDnsServfailResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int = parseDnsQuestion(dnsQuery)?.questionEndOffset ?: dnsQuery.size,
  ): ByteArray {
    val safeLen = questionEndOffset.coerceIn(12, dnsQuery.size)
    val resp = dnsQuery.copyOfRange(0, safeLen)
    resp[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    // RA=1, RCODE=2 (SERVFAIL)
    resp[3] = 0x82.toByte()
    resp[4] = 0x00
    resp[5] = 0x01
    resp[6] = 0x00
    resp[7] = 0x00
    resp[8] = 0x00
    resp[9] = 0x00
    resp[10] = 0x00
    resp[11] = 0x00
    return resp
  }

  private fun relayStreams(
    clientIn: InputStream,
    clientOut: OutputStream,
    remoteIn: InputStream,
    remoteOut: OutputStream,
    clientSocket: Socket? = null,
    tunnelConnection: V2RayOutboundClient.TunnelConnection? = null,
  ) {
    tunnelConnection?.setReadTimeout(75_000)
    relayExecutor.execute {
      try {
        val buf = ByteArray(16384)
        while (running.get()) {
          val n = clientIn.read(buf)
          if (n <= 0) break
          // When the client sends a new request frame (e.g. scrolling Instagram feed on an existing HTTP/2 stream),
          // require the server to respond within 12s; if the remote server is stalled, remoteIn.read() will time out
          // and close the socket so Instagram/Twitter immediately retries on a healthy server!
          tunnelConnection?.setReadTimeout(12_000)
          remoteOut.write(buf, 0, n)
          remoteOut.flush()
        }
      } catch (_: Exception) {
        // Do NOT close tunnelConnection here when clientIn reaches EOF/half-close,
        // because the downstream loop (remoteIn -> clientOut) may still be downloading response data!
      }
    }

    try {
      val buf = ByteArray(16384)
      while (running.get()) {
        val n = remoteIn.read(buf)
        if (n <= 0) break
        tunnelConnection?.setReadTimeout(75_000)
        clientOut.write(buf, 0, n)
        clientOut.flush()
      }
    } catch (_: Exception) {
    } finally {
      try {
        clientSocket?.close()
      } catch (_: Exception) {}
      try {
        tunnelConnection?.close()
      } catch (_: Exception) {}
    }
  }

  private fun readExact(input: InputStream, dst: ByteArray): Boolean {
    var offset = 0
    while (offset < dst.size) {
      val r = input.read(dst, offset, dst.size - offset)
      if (r <= 0) return false
      offset += r
    }
    return true
  }
}
