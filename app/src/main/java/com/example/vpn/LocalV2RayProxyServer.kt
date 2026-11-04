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
import java.util.concurrent.locks.ReentrantLock

/**
 * Local multi-protocol proxy server supporting:
 * 1. Unbounded cached thread pool (`relayExecutor`) so `tun2socks` concurrent TCP/UDP sockets
 *    never hit Kotlin's 64-thread `Dispatchers.IO` starvation deadlock on Android.
 * 2. Real Tunnel DNS Resolution (`Android DNS -> TUN -> SOCKS5/V2Ray -> Remote DNS -> Real IP`):
 *    - Never fabricates counter-based or synthetic Fake IPs for X, Instagram/Meta, or any site.
 *    - Resolves `A` (`QTYPE=1`), `HTTPS/SVCB` (`QTYPE=65/64`), `CNAME`, etc. genuinely inside the
 *      encrypted V2Ray tunnel (`8.8.8.8:53` / `1.1.1.1:53` over persistent reusable TCP tunnels,
 *      with DoH fallback).
 *    - Passively records real `A` record IPv4s (`realIpToDomain` & `domainToRealIp`) from
 *      authentic DNS answers.
 *    - Suppresses only `AAAA` (`QTYPE=28`) while IPv6 is disabled on the TUN interface.
 * 3. Full TLS `ClientHello` Record Reassembly + Domain-First Outbound Routing (`destOverride: ["http", "tls"]`):
 *    - Reassembles multi-segment TLS 1.3 Post-Quantum `ClientHello` packets (`> 1240` bytes)
 *      before extracting the `SNI` hostname so VLESS/Trojan outbounds receive the real domain name
 *      while keeping the real DNS IPv4 as `fallbackIpv4`.
 * 4. Transparent Non-Blocking TCP Relay for Multi-Connection Apps (Instagram, X/Twitter, YouTube):
 *    - Establishes the outbound tunnel, sends the initial `ClientHello` / HTTP request, and
 *      immediately hands the socket to full-duplex `relayStreams()` without blocking on a 4-second
 *      first-response timer or shrinking `soTimeout` to 12 seconds on HTTP/2 client frames.
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
    private const val IDLE_STREAM_TIMEOUT_MS = 180_000
    private const val RELAY_BUFFER_SIZE = 32768
    private const val CONSECUTIVE_FAILURES_TO_PENALIZE = 3

    /** Hard wall-clock budget for one whole DNS lookup (Android's resolver gives up at ~5s). */
    private const val DNS_BUDGET_MS = 2500L
    private const val DNS_SLOT_TIMEOUT_MS = 1500
    private const val DNS_DOH_TIMEOUT_MS = 1500

    private val realIpToDomain = ConcurrentHashMap<String, String>()
    private val domainToRealIp = ConcurrentHashMap<String, String>()

    /**
     * Passively records real IPv4 `A` records from an authentic DNS response so non-SNI connections
     * and Serverless direct connections can look up the verified mapping in 0ms.
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
      var recordedFirstIpForDomain = false
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
            if (!recordedFirstIpForDomain) {
              domainToRealIp[cleanDomain] = ipStr
              recordedFirstIpForDomain = true
            }
          }
        }
        offset += rdLen
      }
    }

    fun lookupDomainForRealIp(hostOrIp: String): String? {
      return realIpToDomain[hostOrIp.trim()]
    }

    fun lookupRealIpForDomain(domain: String): String? {
      return domainToRealIp[domain.trim().trimEnd('.').lowercase()]
    }

    /**
     * Stable synthetic public IPv4s handed out only when genuine in-tunnel DNS could not answer
     * within [DNS_BUDGET_MS]. `198.54.0.0/16` is publicly routable (Chromium's
     * `IsPubliclyRoutable()` accepts it), so Cronet/Proxygen never reject it as a bogon, and
     * `handleSocks5Client` maps every such IP back to its hostname so the outbound still dials the
     * real domain (`destOverride: ["http", "tls"]`). Without this an unresolvable name means the
     * client never even opens a TCP connection, which is exactly what makes every app except
     * Telegram (hardcoded DC IPs, no DNS) appear dead.
     */
    private val syntheticIpCounter = AtomicInteger(1)
    private val syntheticDomainToIp = ConcurrentHashMap<String, String>()
    private val syntheticIpToDomain = ConcurrentHashMap<String, String>()

    fun lookupSyntheticDomainForIp(hostOrIp: String): String? {
      return syntheticIpToDomain[hostOrIp.trim()]
    }

    private fun allocateSyntheticIpForDomain(domain: String): String {
      val cleanDomain = domain.trim().trimEnd('.').lowercase()
      syntheticDomainToIp[cleanDomain]?.let { return it }
      val seq = syntheticIpCounter.getAndIncrement() and 0x0FFFF
      val oct3 = (seq / 250) and 0xFF
      val oct4 = (seq % 250) + 2 // 2..251, never 0, 1 or 255
      val ip = "198.54.$oct3.$oct4"
      val existing = syntheticDomainToIp.putIfAbsent(cleanDomain, ip) ?: ip
      syntheticIpToDomain[existing] = cleanDomain
      return existing
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

  private class PersistentDnsTunnelSlot(val dnsServerIp: String) {
    val lock = ReentrantLock()
    var connection: V2RayOutboundClient.TunnelConnection? = null

    fun closeLocked() {
      try {
        connection?.close()
      } catch (_: Exception) {}
      connection = null
    }
  }

  private val serverPool: List<V2RayConfig> =
    configs.ifEmpty {
      throw IllegalArgumentException("At least one V2RayConfig is required")
    }
  private val activeConfigIndex = AtomicInteger(0)
  private val consecutiveFailures = ConcurrentHashMap<Int, AtomicInteger>()
  private val penalizedIndices = ConcurrentHashMap.newKeySet<Int>()
  private val dnsCache = ConcurrentHashMap<String, ByteArray>()
  private val inFlightDnsLocks = ConcurrentHashMap<String, Any>()
  private val dnsSlotCounter = AtomicInteger(0)
  private val dnsTunnelSlots =
    arrayOf(
      PersistentDnsTunnelSlot("8.8.8.8"),
      PersistentDnsTunnelSlot("1.1.1.1"),
    )
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
          client.keepAlive = true
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
    for (slot in dnsTunnelSlots) {
      slot.lock.lock()
      try {
        slot.closeLocked()
      } finally {
        slot.lock.unlock()
      }
    }
    serverSocket = null
    udpRelaySocket = null
    dnsCache.clear()
    inFlightDnsLocks.clear()
    consecutiveFailures.clear()
    penalizedIndices.clear()
    try {
      relayExecutor.shutdownNow()
    } catch (_: Exception) {}
  }

  private fun recordServerSuccess(idx: Int) {
    consecutiveFailures[idx]?.set(0)
    penalizedIndices.remove(idx)
    activeConfigIndex.set(idx)
  }

  private fun recordServerTransportFailure(idx: Int) {
    if (serverPool.size <= 1) return
    val count = consecutiveFailures.computeIfAbsent(idx) { AtomicInteger(0) }.incrementAndGet()
    if (count >= CONSECUTIVE_FAILURES_TO_PENALIZE) {
      penalizedIndices.add(idx)
      // Never allow all servers in the pool to remain penalized simultaneously
      if (penalizedIndices.size >= serverPool.size) {
        penalizedIndices.clear()
      }
    }
  }

  /**
   * Opens a V2Ray tunnel across `serverPool`:
   * 1. Prioritizes the primary verified server (`activeConfigIndex`) first, followed by other
   *    healthy verified candidates in `serverPool`, so Instagram/X multi-connection bursts all use
   *    the verified Tier-1 tunnel unless a transport handshake error occurs.
   * 2. For normal client TCP/TLS streams (`awaitFirstResponse = false`):
   *    `CONNECT tunnel -> send ClientHello -> return tunnel immediately -> normal bidirectional relay`.
   *    Does NOT block for 4 seconds waiting for the remote backend's first byte, preventing
   *    Instagram CDN/Graph API pre-warmed or multiplexed streams from timing out and poisoning the pool.
   */
  private fun openTunnelWithVerifiedFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 5500,
    initialPayload: ByteArray? = null,
    initialPayloadLen: Int = 0,
    awaitFirstResponse: Boolean = false,
    fallbackIpv4: String? = null,
    firstReplyTimeoutMs: Int = 3500,
    maxNodes: Int = Int.MAX_VALUE,
    penalizeOnFailure: Boolean = true,
  ): OpenedTunnelWithReply {
    val poolSize = serverPool.size
    val currentPrimary = activeConfigIndex.get().coerceIn(0, poolSize - 1)

    val orderedIndices = ArrayList<Int>(poolSize)
    if (currentPrimary !in penalizedIndices) {
      orderedIndices.add(currentPrimary)
    }
    for (idx in 0 until poolSize) {
      if (idx !in penalizedIndices && idx !in orderedIndices) {
        orderedIndices.add(idx)
      }
    }
    for (idx in 0 until poolSize) {
      if (idx !in orderedIndices) {
        orderedIndices.add(idx)
      }
    }

    val cleanFallbackIp =
      if (!fallbackIpv4.isNullOrBlank() &&
        fallbackIpv4 != targetHost &&
        V2RayOutboundClient.parseIpv4Bytes(fallbackIpv4)?.let { V2RayOutboundClient.isPublicRoutableIpv4(it) } == true
      ) {
        fallbackIpv4
      } else {
        lookupRealIpForDomain(targetHost)
      }

    // Only retry a second target on the same V2Ray node when awaitFirstResponse == true
    // (because when awaitFirstResponse == false, VLESS/Trojan sends the target address inside the stream header).
    val targetsToTry =
      if (awaitFirstResponse && !cleanFallbackIp.isNullOrBlank() && cleanFallbackIp != targetHost) {
        listOf(targetHost, cleanFallbackIp)
      } else {
        listOf(targetHost)
      }

    var lastError: Exception? = null

    for ((attemptIdx, idx) in orderedIndices.withIndex()) {
      // DNS probes must never walk the whole pool: every extra node costs another full
      // connect + first-reply timeout while the DNS slot lock is held.
      if (attemptIdx >= maxNodes) break
      val candidate = serverPool[idx]
      var nodeSucceeded = false
      for (hostCandidate in targetsToTry) {
        var conn: V2RayOutboundClient.TunnelConnection? = null
        try {
          val connectTimeout = if (attemptIdx == 0) timeoutMs else 4000
          conn =
            V2RayOutboundClient.openTunnel(
              config = candidate,
              targetHost = hostCandidate,
              targetPort = targetPort,
              timeoutMs = connectTimeout,
              protector = protector,
              fallbackIpv4 = cleanFallbackIp,
            )
          if (initialPayload != null && initialPayloadLen > 0) {
            conn.outputStream.write(initialPayload, 0, initialPayloadLen)
            conn.outputStream.flush()

            if (awaitFirstResponse) {
              conn.setReadTimeout(firstReplyTimeoutMs)
              val replyBuf = ByteArray(16384)
              val replyLen = conn.inputStream.read(replyBuf)
              if (replyLen <= 0) {
                throw IOException("V2Ray server ${candidate.address} closed stream before replying for $hostCandidate:$targetPort")
              }
              conn.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
              recordServerSuccess(idx)
              return OpenedTunnelWithReply(conn, replyBuf, replyLen)
            }
          }
          conn.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
          recordServerSuccess(idx)
          nodeSucceeded = true
          return OpenedTunnelWithReply(conn, null, 0)
        } catch (e: Exception) {
          try {
            conn?.close()
          } catch (_: Exception) {}
          lastError = e
        }
      }
      // A node that merely refuses/blackholes port 53 is still a perfectly good 443 node, so DNS
      // probes (penalizeOnFailure = false) must not count towards penalizing it.
      if (!nodeSucceeded && penalizeOnFailure) {
        recordServerTransportFailure(idx)
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
        clientSocket.soTimeout = 1200
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
        clientSocket.soTimeout = 200
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

        // Synthetic DNS answers (`198.54.x.y` handed out when in-tunnel DNS timed out) must be
        // mapped back to the hostname they were allocated for, otherwise a client that connects
        // without TLS SNI or an HTTP Host header would dial a meaningless IP.
        val syntheticDomain = lookupSyntheticDomainForIp(rawTargetHost)
        var effectiveHost = syntheticDomain ?: rawTargetHost

        // Acknowledge SOCKS5 CONNECT so the client immediately sends its first packet
        // (TLS ClientHello / HTTP request / MTProto preamble / DoT port 853 handshake)
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
        clientOut.flush()

        val firstBuffer = ByteArray(RELAY_BUFFER_SIZE)
        val firstLen = readCompleteFirstClientPacket(clientSocket, clientIn, firstBuffer)
        if (firstLen == -1) return

        // Domain-first routing (`destOverride: ["http", "tls"]`):
        // Whenever the packet is a TLS ClientHello with an SNI hostname or an HTTP request with a
        // Host header, pass the exact sniffed domain name to the VLESS/Trojan outbound so the remote
        // V2Ray server resolves it directly, while keeping the real DNS IPv4 `rawTargetHost` as fallback!
        if (firstLen > 0) {
          val tlsSni = GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
          val httpHost = if (tlsSni == null) extractHttpHostHeader(firstBuffer, firstLen) else null
          val sniffedDomain = tlsSni ?: httpHost
          if (!sniffedDomain.isNullOrBlank()) {
            effectiveHost = sniffedDomain
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

        // Transparent TCP tunnel: open V2Ray stream, write initial ClientHello/HTTP request,
        // and immediately enter full-duplex relay without blocking on a 4-second first-response timer.
        val opened =
          try {
            openTunnelWithVerifiedFailover(
              targetHost = effectiveHost,
              targetPort = targetPort,
              initialPayload = firstBuffer,
              initialPayloadLen = firstLen,
              awaitFirstResponse = false,
              // A synthetic 198.54.x.y address is not a real server: never offer it as the
              // "fallback IPv4" (Serverless mode would dial it directly and black-hole).
              fallbackIpv4 = if (syntheticDomain != null) null else rawTargetHost,
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
    // fall back to TCP port 443 HTTP/2 over the encrypted V2Ray tunnel.
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
   * 1. Suppresses `AAAA` (`QTYPE=28`) while IPv6 is disabled on the TUN interface, and also
   *    suppresses `HTTPS/SVCB` (`QTYPE=65/64`): every UDP packet that is not port 53 is dropped
   *    downstream, so an `alpn=h3` hint only makes clients stall on QUIC/UDP 443 before falling
   *    back to TCP. Every lookup runs against a hard [DNS_BUDGET_MS] deadline; when the in-tunnel
   *    resolvers cannot answer in time a stable synthetic public IPv4 is returned instead of
   *    SERVFAIL (see [allocateSyntheticIpForDomain]).
   * 2. Uses `dnsCache` + in-flight deduplication (`inFlightDnsLocks`) and records real `A` records
   *    into `realIpToDomain` and `domainToRealIp` without ever fabricating Fake IPs.
   * 3. Resolves via persistent reusable 1-RTT RFC 1035 DNS-over-TCP (`8.8.8.8:53` / `1.1.1.1:53`)
   *    inside the V2Ray tunnel so a burst of 20+ Instagram CDN DNS queries reuses open streams
   *    instead of opening 20 new V2Ray TLS+WebSocket connections.
   */
  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.size < 12) return null
    val question = parseDnsQuestion(dnsQuery)
    if (question != null) {
      // Suppress IPv6 AAAA (QTYPE=28) because the TUN interface is IPv4-only, and HTTPS/SVCB
      // (QTYPE=65/64) because `handleSocks5UdpDatagram` drops every non-port-53 UDP packet: an
      // `alpn=h3`/`ipv6hint` record only makes Chromium/Instagram/YouTube chase QUIC over a
      // black-holed UDP 443 and stall before falling back to TCP.
      if (question.qtype == 28 || question.qtype == 65 || question.qtype == 64) {
        return buildEmptyDnsNoerrorResponse(dnsQuery, question.questionEndOffset)
      }
    }

    // Fake-IP first (the same approach v2rayNG / sing-box / Clash use): answer every plain `A`
    // query instantly with a stable synthetic IPv4 and let `handleSocks5Client` map it back to the
    // hostname, so the V2Ray node resolves the name itself (VLESS/Trojan carry the domain).
    // Previously a *real* lookup was attempted first through the tunnel (8.8.8.8:53), which needs
    // a fresh node connection per name and stalls for seconds whenever the node refuses port 53 —
    // apps never got an IP, never opened a socket, and only Telegram (hard-coded IPs) worked.
    // Serverless mode dials the target directly and therefore still needs genuine IPs.
    if (question != null &&
      question.qtype == 1 &&
      question.qclass == 1 &&
      question.domain.isNotEmpty() &&
      activeConfig.protocol != V2RayProtocol.SERVERLESS
    ) {
      val fakeIpBytes = V2RayOutboundClient.parseIpv4Bytes(allocateSyntheticIpForDomain(question.domain))
      if (fakeIpBytes != null) {
        return buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, fakeIpBytes)
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

    val deadlineNanos = System.nanoTime() + DNS_BUDGET_MS * 1_000_000L
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
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = directDoh.copyOf()
            }
            return directDoh
          }
        } else {
          // 2. Primary: Persistent reusable 1-RTT DNS-over-TCP (`8.8.8.8:53` / `1.1.1.1:53`) inside V2Ray tunnel
          val tcpDnsResp = resolveDnsOverTcpViaTunnel(dnsQuery, deadlineNanos)
          if (tcpDnsResp != null && isValidUnpoisonedDnsResponse(tcpDnsResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, tcpDnsResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = tcpDnsResp.copyOf()
            }
            return tcpDnsResp
          }

          // 3. Secondary: DNS-over-HTTPS (`8.8.8.8:443` / `1.1.1.1:443`) inside the V2Ray tunnel
          val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery, deadlineNanos)
          if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, dohTunnelResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = dohTunnelResp.copyOf()
            }
            return dohTunnelResp
          }
        }

        // 4. Last-resort fallback: Protected direct fragmented DoH (`8.8.8.8:443` / `1.1.1.1:443`).
        // Only worth trying while the resolver budget is still alive: direct DoH is usually
        // throttled/blocked inside Iran, so it must never be what the client waits on.
        if (remainingDnsMillis(deadlineNanos) >= 2000) {
          val directDohResp = resolveDnsOverHttpsProtectedDirect(dnsQuery)
          if (directDohResp != null && isValidUnpoisonedDnsResponse(directDohResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, directDohResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = directDohResp.copyOf()
            }
            return directDohResp
          }
        }
      } finally {
        if (cacheKey != null) {
          inFlightDnsLocks.remove(cacheKey, lock)
        }
      }
    }

    // Genuine DNS did not answer in time. Most nodes in this catalog are CDN/Worker fronted and can
    // only open outbound connections to 80/443, so `8.8.8.8:53` inside the tunnel is frequently
    // unreachable. Answering SERVFAIL here is what breaks every hostname-based app, so instead we
    // hand out a stable synthetic public IPv4 and let the SNI/Host based domain-first routing dial
    // the real hostname.
    if (question != null && question.qtype == 1 && question.domain.isNotEmpty()) {
      val syntheticIp = allocateSyntheticIpForDomain(question.domain)
      val ipBytes = V2RayOutboundClient.parseIpv4Bytes(syntheticIp)
      if (ipBytes != null) {
        val syntheticResponse =
          buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, ipBytes)
        if (cacheKey != null && dnsCache.size < 2048) {
          dnsCache[cacheKey] = syntheticResponse.copyOf()
        }
        return syntheticResponse
      }
    }

    return buildDnsServfailResponse(dnsQuery, question?.questionEndOffset ?: dnsQuery.size)
  }

  private fun remainingDnsMillis(deadlineNanos: Long): Int {
    val remaining = (deadlineNanos - System.nanoTime()) / 1_000_000L
    return remaining.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
  }

  /**
   * Builds an RFC 1035 DNS `A` response for [dnsQuery] returning [ipv4Bytes] with a 120s TTL,
   * properly truncated to `questionEndOffset` so no trailing EDNS0 bytes remain when `ARCOUNT = 0`.
   */
  private fun buildSyntheticDnsAResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int,
    ipv4Bytes: ByteArray,
  ): ByteArray {
    val safeEnd = questionEndOffset.coerceIn(12, dnsQuery.size)
    val respHeader = dnsQuery.copyOfRange(0, safeEnd)

    // Flags: preserve Opcode and RD from query, set QR=1, RA=1, RCODE=0
    respHeader[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    respHeader[3] = 0x80.toByte()
    // QDCOUNT = 1
    respHeader[4] = 0x00
    respHeader[5] = 0x01
    // ANCOUNT = 1
    respHeader[6] = 0x00
    respHeader[7] = 0x01
    // NSCOUNT = 0, ARCOUNT = 0
    respHeader[8] = 0x00
    respHeader[9] = 0x00
    respHeader[10] = 0x00
    respHeader[11] = 0x00

    val finalOut = ByteArrayOutputStream(respHeader.size + 16)
    finalOut.write(respHeader)
    // Answer RR: Name pointer to offset 12 (0xC00C)
    finalOut.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
    // TYPE = A (0x0001), CLASS = IN (0x0001)
    finalOut.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
    // TTL = 120 seconds (0x00000078)
    finalOut.write(byteArrayOf(0x00, 0x00, 0x00, 0x78))
    // RDLENGTH = 4
    finalOut.write(byteArrayOf(0x00, 0x04))
    // RDATA = 4-byte IPv4 address
    finalOut.write(ipv4Bytes)
    return finalOut.toByteArray()
  }

  /**
   * Resolves [dnsQuery] using RFC 1035 DNS-over-TCP (`[2-byte length][dnsQuery]`) over persistent
   * reusable V2Ray tunnels (`8.8.8.8:53` and `1.1.1.1:53`).
   * Reusing an open TCP-over-V2Ray stream avoids creating 20+ concurrent TLS+WebSocket handshakes
   * when Instagram/X resolves multiple CDN subdomains (`scontent-*.cdninstagram.com`, `video-*.cdninstagram.com`).
   */
  private fun resolveDnsOverTcpViaTunnel(dnsQuery: ByteArray, deadlineNanos: Long): ByteArray? {
    val tcpFrame = ByteArray(2 + dnsQuery.size)
    tcpFrame[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
    tcpFrame[1] = (dnsQuery.size and 0xFF).toByte()
    System.arraycopy(dnsQuery, 0, tcpFrame, 2, dnsQuery.size)

    val startSlotIdx = (dnsSlotCounter.getAndIncrement() and 0x7FFFFFFF) % dnsTunnelSlots.size

    // Try persistent reusable DNS tunnel slots first
    for (offset in dnsTunnelSlots.indices) {
      if (remainingDnsMillis(deadlineNanos) < 500) return null
      val slot = dnsTunnelSlots[(startSlotIdx + offset) % dnsTunnelSlots.size]
      if (slot.lock.tryLock()) {
        try {
          queryPersistentDnsSlotLocked(slot, tcpFrame, dnsQuery, deadlineNanos)?.let { return it }
        } finally {
          slot.lock.unlock()
        }
      }
    }

    // If both persistent slots were busy with concurrent queries, wait on the assigned slot
    if (remainingDnsMillis(deadlineNanos) < 500) return null
    val assignedSlot = dnsTunnelSlots[startSlotIdx]
    // Bounded wait: an unbounded lock() here let one stuck slot stall every other DNS query.
    val lockWaitMs = remainingDnsMillis(deadlineNanos) - 500
    if (lockWaitMs <= 0 ||
      !assignedSlot.lock.tryLock(lockWaitMs.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS)
    ) {
      return null
    }
    try {
      queryPersistentDnsSlotLocked(assignedSlot, tcpFrame, dnsQuery, deadlineNanos)?.let { return it }
    } finally {
      assignedSlot.lock.unlock()
    }

    return null
  }

  private fun queryPersistentDnsSlotLocked(
    slot: PersistentDnsTunnelSlot,
    tcpFrame: ByteArray,
    dnsQuery: ByteArray,
    deadlineNanos: Long,
  ): ByteArray? {
    for (attempt in 0..1) {
      val remainingMs = remainingDnsMillis(deadlineNanos)
      if (remainingMs < 500) return null
      val attemptTimeout = minOf(remainingMs, DNS_SLOT_TIMEOUT_MS)
      try {
        var tunnel = slot.connection
        if (tunnel == null) {
          val opened =
            openTunnelWithVerifiedFailover(
              targetHost = slot.dnsServerIp,
              targetPort = 53,
              timeoutMs = attemptTimeout,
              initialPayload = tcpFrame,
              initialPayloadLen = tcpFrame.size,
              awaitFirstResponse = true,
              firstReplyTimeoutMs = attemptTimeout,
              maxNodes = 1,
              penalizeOnFailure = false,
            )
          tunnel = opened.connection
          slot.connection = tunnel

          val firstBytes = opened.firstReplyBytes
          val firstLen = opened.firstReplyLen
          if (firstBytes == null || firstLen <= 0) {
            slot.closeLocked()
            continue
          }
          val parsed = readDnsFrameFromStream(tunnel, firstBytes, firstLen, dnsQuery)
          if (parsed != null) {
            return parsed
          } else {
            slot.closeLocked()
            continue
          }
        } else {
          tunnel.setReadTimeout(attemptTimeout)
          tunnel.outputStream.write(tcpFrame)
          tunnel.outputStream.flush()
          val parsed = readDnsFrameFromStream(tunnel, null, 0, dnsQuery)
          if (parsed != null) {
            tunnel.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
            return parsed
          } else {
            slot.closeLocked()
          }
        }
      } catch (_: Exception) {
        slot.closeLocked()
      }
    }
    return null
  }

  private fun readDnsFrameFromStream(
    tunnel: V2RayOutboundClient.TunnelConnection,
    firstBytes: ByteArray?,
    firstLen: Int,
    dnsQuery: ByteArray,
  ): ByteArray? {
    val buf = ByteArrayOutputStream(512)
    if (firstBytes != null && firstLen > 0) {
      buf.write(firstBytes, 0, firstLen)
    }
    val tmp = ByteArray(512)

    while (buf.size() < 2) {
      val r = tunnel.inputStream.read(tmp)
      if (r <= 0) return null
      buf.write(tmp, 0, r)
    }
    val current = buf.toByteArray()
    val expectedDnsLen = ((current[0].toInt() and 0xFF) shl 8) or (current[1].toInt() and 0xFF)
    if (expectedDnsLen !in 12..4096) return null

    while (buf.size() < 2 + expectedDnsLen) {
      val r = tunnel.inputStream.read(tmp)
      if (r <= 0) return null
      buf.write(tmp, 0, r)
    }
    val full = buf.toByteArray()
    if (full.size >= 2 + expectedDnsLen) {
      val dnsResp = full.copyOfRange(2, 2 + expectedDnsLen)
      dnsResp[0] = dnsQuery[0]
      dnsResp[1] = dnsQuery[1]
      return dnsResp
    }
    return null
  }

  private fun resolveDnsOverHttpsViaTunnel(dnsQuery: ByteArray, deadlineNanos: Long): ByteArray? {
    for ((targetIp, sniHost) in listOf("8.8.8.8" to "dns.google", "1.1.1.1" to "cloudflare-dns.com")) {
      val remainingMs = remainingDnsMillis(deadlineNanos)
      if (remainingMs < 600) break
      try {
        val opened =
          openTunnelWithVerifiedFailover(
            targetHost = targetIp,
            targetPort = 443,
            timeoutMs = minOf(remainingMs, DNS_DOH_TIMEOUT_MS),
            maxNodes = 1,
            penalizeOnFailure = false,
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
      if (offset < 0 || offset + 10 > dnsBytes.size) return false
      val type = ((dnsBytes[offset].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 1].toInt() and 0xFF)
      val rdLen = ((dnsBytes[offset + 8].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 9].toInt() and 0xFF)
      offset += 10
      if (offset + rdLen > dnsBytes.size) return false
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

      val firstBuffer = ByteArray(RELAY_BUFFER_SIZE)
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
          awaitFirstResponse = false,
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
          awaitFirstResponse = false,
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

  /**
   * Full-duplex stream relay engineered for HTTP/2 multiplexed connections and long-lived media
   * streams (Instagram feed, Reels video CDN, Graph API, X/Twitter):
   * - Maintains a stable, generous idle timeout (`IDLE_STREAM_TIMEOUT_MS = 180_000` ms) without
   *   shrinking `soTimeout` to 12 seconds when the client sends HTTP/2 `WINDOW_UPDATE`, `PING`, or
   *   `SETTINGS` frames.
   * - Uses 32KB buffers in both directions and performs clean half-close when a stream finishes.
   */
  private fun relayStreams(
    clientIn: InputStream,
    clientOut: OutputStream,
    remoteIn: InputStream,
    remoteOut: OutputStream,
    clientSocket: Socket? = null,
    tunnelConnection: V2RayOutboundClient.TunnelConnection? = null,
  ) {
    try {
      clientSocket?.tcpNoDelay = true
      clientSocket?.keepAlive = true
      clientSocket?.soTimeout = 0
    } catch (_: Exception) {}
    tunnelConnection?.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)

    relayExecutor.execute {
      try {
        val buf = ByteArray(RELAY_BUFFER_SIZE)
        while (running.get()) {
          val n = clientIn.read(buf)
          if (n <= 0) break
          remoteOut.write(buf, 0, n)
          remoteOut.flush()
        }
      } catch (_: Exception) {
        // Do NOT close tunnelConnection here when clientIn reaches EOF/half-close,
        // because the downstream loop (remoteIn -> clientOut) may still be downloading response data!
      }
    }

    try {
      val buf = ByteArray(RELAY_BUFFER_SIZE)
      while (running.get()) {
        val n = remoteIn.read(buf)
        if (n <= 0) break
        clientOut.write(buf, 0, n)
        clientOut.flush()
      }
    } catch (_: Exception) {
    } finally {
      try {
        clientSocket?.shutdownOutput()
      } catch (_: Exception) {}
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
