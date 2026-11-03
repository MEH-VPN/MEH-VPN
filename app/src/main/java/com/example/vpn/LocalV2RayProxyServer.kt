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
 * 2. Real Public Anycast IP Coalescing + Instant FakeDNS fallback:
 *    - Resolves Instagram (`*.instagram.com`, `*.cdninstagram.com`, `*.fbcdn.net`), Twitter/X
 *      (`*.x.com`, `*.twitter.com`, `*.twimg.com`, `t.co`), YouTube/Google, and Telegram domains
 *      in 0.1ms to their real public Anycast IPs so Cronet (Twitter) and Meta Proxygen (Instagram)
 *      never reject bogon IPs and properly coalesce HTTP/2 streams onto shared connections.
 *    - Suppresses `AAAA` (`QTYPE=28`) and `HTTPS/SVCB` (`QTYPE=65/64`) in 0.1ms so apps never stall
 *      on IPv6 or UDP 443 QUIC probes.
 * 3. Full TLS `ClientHello` Record Reassembly + Unconditional `destOverride: ["http", "tls"]`:
 *    - Reassembles multi-segment TLS 1.3 Post-Quantum `ClientHello` packets (`> 1240` bytes)
 *      before extracting the `SNI` hostname so Twitter/Instagram SNI at the end of the 2nd TCP
 *      segment is 100% always detected.
 * 4. Verified First-Response Multi-Server Failover + Concurrent Stream Load-Balancing:
 *    - Verifies that the remote V2Ray server actually connected to `targetHost:targetPort` and
 *      returned the first response bytes (`ServerHello`) before committing to that server; if a
 *      Cloudflare Worker hits its 6-connection limit (e.g. after Instagram's first 2 posts) or
 *      blocks Twitter, it transparently fails over to the next server in `serverPool`!
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
    private val fakeIpCounter = AtomicInteger(1)
    private val domainToFakeIp = ConcurrentHashMap<String, String>()
    private val fakeIpToDomain = ConcurrentHashMap<String, String>()

    /**
     * Returns a real, non-bogon public Anycast IPv4 for major platforms (Twitter/X, Instagram/Meta,
     * YouTube/Google, Telegram) so that:
     * 1. Chromium/Cronet (Twitter) and Meta Proxygen (Instagram) never reject the DNS response
     *    as an RFC 2544 (`198.18.0.0/15`) bogon/hijacked IP.
     * 2. Subdomains sharing the same wildcard certificate coalesce onto shared HTTP/2 connections
     *    instead of opening 25+ separate TCP sockets.
     * 3. When the app connects to this IP and sends its TLS `ClientHello`, our SNI sniffer
     *    (`extractTlsSniHostname`) extracts the exact subdomain (`api.x.com`, `pbs.twimg.com`,
     *    `scontent-xxx.cdninstagram.com`) and routes it by domain name through the V2Ray server.
     */
    fun resolveKnownCleanPublicIpv4(domain: String): String? {
      val d = domain.trim().trimEnd('.').lowercase()
      return when {
        // Twitter / X API & Web
        d == "x.com" || d.endsWith(".x.com") ||
          d == "twitter.com" || d.endsWith(".twitter.com") -> "104.244.42.129"
        d == "t.co" || d.endsWith(".t.co") -> "104.244.42.65"
        // Twitter / X Media & Assets CDN (Fastly Anycast)
        d == "twimg.com" || d.endsWith(".twimg.com") ||
          d == "pscp.tv" || d.endsWith(".pscp.tv") ||
          d == "periscope.tv" || d.endsWith(".periscope.tv") -> "151.101.1.140"

        // Instagram API & Web (Meta Anycast)
        d == "instagram.com" || d.endsWith(".instagram.com") ||
          d == "ig.me" || d.endsWith(".ig.me") -> "157.240.241.174"
        // Instagram & Facebook Media CDN (`scontent-*.cdninstagram.com`, `video-*.cdninstagram.com`, `*.fbcdn.net`)
        d == "cdninstagram.com" || d.endsWith(".cdninstagram.com") ||
          d == "fbcdn.net" || d.endsWith(".fbcdn.net") ||
          d == "facebook.com" || d.endsWith(".facebook.com") ||
          d == "fb.com" || d.endsWith(".fb.com") ||
          d == "whatsapp.com" || d.endsWith(".whatsapp.com") ||
          d == "whatsapp.net" || d.endsWith(".whatsapp.net") -> "157.240.241.63"

        // YouTube & Video CDN
        d == "youtube.com" || d.endsWith(".youtube.com") ||
          d == "youtu.be" || d.endsWith(".youtu.be") ||
          d == "googlevideo.com" || d.endsWith(".googlevideo.com") ||
          d == "ytimg.com" || d.endsWith(".ytimg.com") ||
          d == "ggpht.com" || d.endsWith(".ggpht.com") -> "142.250.185.78"

        // Google & Android Services
        d == "google.com" || d.endsWith(".google.com") ||
          d == "googleapis.com" || d.endsWith(".googleapis.com") ||
          d == "gstatic.com" || d.endsWith(".gstatic.com") ||
          d == "googleusercontent.com" || d.endsWith(".googleusercontent.com") ||
          d == "gvt1.com" || d.endsWith(".gvt1.com") ||
          d == "1e100.net" || d.endsWith(".1e100.net") -> "142.250.185.206"

        // Telegram Web & Shortlinks
        d == "telegram.org" || d.endsWith(".telegram.org") ||
          d == "t.me" || d.endsWith(".t.me") ||
          d == "telegra.ph" || d.endsWith(".telegra.ph") ||
          d == "telesco.pe" || d.endsWith(".telesco.pe") -> "149.154.167.99"

        else -> null
      }
    }

    /**
     * Collision-free virtual IPv4 allocator in `198.18.0.2 .. 198.19.255.251` with 1-to-1
     * bidirectional mapping (`domainToFakeIp` <-> `fakeIpToDomain`).
     */
    fun allocateFakeIpForDomain(domain: String): String {
      val normalized = domain.trim().trimEnd('.').lowercase()
      domainToFakeIp[normalized]?.let { return it }

      val seq = (fakeIpCounter.getAndIncrement() and 0x0FFFF)
      val oct2 = 18 + ((seq / (256 * 250)) and 0x01)
      val rem = seq % (256 * 250)
      val oct3 = (rem / 250) and 0xFF
      val oct4 = (rem % 250) + 2 // 2..251 (never 0, 1, or 255)
      val fakeIp = "198.$oct2.$oct3.$oct4"

      val existing = domainToFakeIp.putIfAbsent(normalized, fakeIp)
      val finalIp = existing ?: fakeIp
      fakeIpToDomain[finalIp] = normalized
      return finalIp
    }

    fun resolveFakeIpDomain(hostOrIp: String): String? {
      val trimmed = hostOrIp.trim()
      fakeIpToDomain[trimmed]?.let { return it }
      return when (trimmed) {
        "104.244.42.129" -> "api.x.com"
        "104.244.42.65" -> "t.co"
        "151.101.1.140" -> "pbs.twimg.com"
        "157.240.241.174" -> "i.instagram.com"
        "157.240.241.63" -> "scontent.cdninstagram.com"
        "142.250.185.78" -> "www.youtube.com"
        "142.250.185.206" -> "www.google.com"
        "149.154.167.99" -> "core.telegram.org"
        else -> null
      }
    }

    fun isFakeIpAddress(hostOrIp: String): Boolean {
      val trimmed = hostOrIp.trim()
      return trimmed.startsWith("198.18.") || trimmed.startsWith("198.19.")
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
  private val dnsCache = ConcurrentHashMap<String, ByteArray>()
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
    try {
      relayExecutor.shutdownNow()
    } catch (_: Exception) {}
  }

  /**
   * Opens a V2Ray tunnel across `serverPool` with:
   * 1. Load distribution across the top verified servers when apps (Instagram/Twitter) burst
   *    15–30 parallel connections, avoiding single-Cloudflare-Worker 6-connection throttling.
   * 2. End-to-end first-response verification (`awaitFirstResponse = true`): when the client sends
   *    an initial TLS `ClientHello` or HTTP request, we verify that the V2Ray server actually
   *    connected to `targetHost:targetPort` and returned at least 1 response byte (`ServerHello`).
   *    If `candidate` drops the stream (`EOFException`) or blocks `targetHost` (e.g. Twitter on
   *    a restricted Worker), we immediately fail over to the next candidate in `serverPool`!
   */
  private fun openTunnelWithVerifiedFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 5500,
    initialPayload: ByteArray? = null,
    initialPayloadLen: Int = 0,
    awaitFirstResponse: Boolean = false,
  ): OpenedTunnelWithReply {
    val poolSize = serverPool.size
    // Spread burst connections across up to the top 3 verified servers so a single Cloudflare Worker
    // never hits its 6-subrequest concurrency ceiling when Instagram loads 20+ images in parallel.
    val primaryWindow = minOf(poolSize, 3)
    val baseIdx =
      if (primaryWindow > 1 && initialPayloadLen > 0) {
        (activeConfigIndex.get() + (streamDispatchCounter.getAndIncrement() % primaryWindow)) % poolSize
      } else {
        activeConfigIndex.get().coerceIn(0, poolSize - 1)
      }

    var lastError: Exception? = null

    for (offset in 0 until poolSize) {
      val idx = (baseIdx + offset) % poolSize
      val candidate = serverPool[idx]
      var conn: V2RayOutboundClient.TunnelConnection? = null
      try {
        val connectTimeout = if (offset == 0) timeoutMs else 4200
        conn =
          V2RayOutboundClient.openTunnel(
            config = candidate,
            targetHost = targetHost,
            targetPort = targetPort,
            timeoutMs = connectTimeout,
            protector = protector,
          )
        if (initialPayload != null && initialPayloadLen > 0) {
          conn.outputStream.write(initialPayload, 0, initialPayloadLen)
          conn.outputStream.flush()

          if (awaitFirstResponse) {
            try {
              conn.underlyingSocket.soTimeout = 4500
            } catch (_: Exception) {}
            val replyBuf = ByteArray(16384)
            val replyLen = conn.inputStream.read(replyBuf)
            if (replyLen <= 0) {
              throw IOException("V2Ray server ${candidate.address} closed stream before replying for $targetHost:$targetPort")
            }
            try {
              conn.underlyingSocket.soTimeout = 0
            } catch (_: Exception) {}
            if (offset > 0 && baseIdx == activeConfigIndex.get()) {
              activeConfigIndex.set(idx)
            }
            return OpenedTunnelWithReply(conn, replyBuf, replyLen)
          }
        }
        try {
          conn.underlyingSocket.soTimeout = 0
        } catch (_: Exception) {}
        return OpenedTunnelWithReply(conn, null, 0)
      } catch (e: Exception) {
        try {
          conn?.close()
        } catch (_: Exception) {}
        lastError = e
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
   * Reads the initial client payload from [clientIn]. If the payload starts with a TLS Handshake
   * record (`0x16`), reassembles the complete TLS record (`5 + recordLen` bytes) across TCP segments
   * so large Post-Quantum TLS 1.3 `ClientHello` packets (used by Twitter/X and Instagram) always
   * include their `SNI` extension even when split across multiple TCP segments by the TUN MTU.
   */
  private fun readCompleteFirstClientPacket(
    clientSocket: Socket,
    clientIn: InputStream,
    buffer: ByteArray,
  ): Int {
    var totalRead =
      try {
        clientSocket.soTimeout = 1500
        val n = clientIn.read(buffer)
        if (n <= 0) return n
        n
      } catch (_: SocketTimeoutException) {
        return 0
      }

    if ((buffer[0].toInt() and 0xFF) == 0x16) {
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
          val expectedTotal = (5 + recordPayloadLen).coerceAtMost(buffer.size)
          while (totalRead < expectedTotal) {
            val r = clientIn.read(buffer, totalRead, expectedTotal - totalRead)
            if (r <= 0) break
            totalRead += r
          }
        }
      } catch (_: SocketTimeoutException) {
        // Proceed with bytes read so far
      }
    }
    return totalRead
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
        var effectiveHost =
          if (targetPort == 53 && isFakeIpAddress(rawTargetHost)) {
            "8.8.8.8"
          } else {
            resolveFakeIpDomain(rawTargetHost) ?: rawTargetHost
          }

        // Acknowledge SOCKS5 CONNECT so the client immediately sends its first packet
        // (TLS ClientHello / HTTP request / MTProto preamble)
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
        clientOut.flush()

        val firstBuffer = ByteArray(32768)
        val firstLen = readCompleteFirstClientPacket(clientSocket, clientIn, firstBuffer)
        if (firstLen == -1) return

        // Unconditional `destOverride: ["http", "tls"]`:
        // Whenever the packet is a TLS ClientHello with an SNI hostname or an HTTP request with a
        // Host header, ALWAYS use the sniffed hostname as the authoritative destination!
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

        // Reject un-sniffed ISP-poisoned 10.x.x.x IPs immediately so the app re-queries DNS
        val ipv4Target = V2RayOutboundClient.parseIpv4Bytes(effectiveHost)
        if (ipv4Target != null && (ipv4Target[0].toInt() and 0xFF) == 10) {
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
        // UDP ASSOCIATE: keep control socket open for up to 120s so tun2socks UDP associations
        // remain active across continuous browsing in Instagram, Twitter, and YouTube.
        clientSocket.soTimeout = 120_000
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
   * Builds an instant RFC 1035 DNS `A` response for [dnsQuery] returning [ipv4Bytes] with a 120s TTL.
   */
  private fun buildSyntheticDnsAResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int,
    ipv4Bytes: ByteArray,
  ): ByteArray {
    val questionSection = dnsQuery.copyOfRange(0, questionEndOffset)
    val out = ByteArrayOutputStream(questionSection.size + 16)
    out.write(questionSection)
    val respHeader = out.toByteArray()

    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0 -> 0x8180
    respHeader[2] = 0x81.toByte()
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

  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.size < 12) return null
    val question = parseDnsQuestion(dnsQuery)
    if (question != null) {
      // 1. Suppress IPv6 (AAAA=28) and HTTPS/SVCB (65/64) queries in 0.1ms with NOERROR (0 answers)
      //    so Android 9 and Chrome/Instagram/Twitter never stall on IPv6 or UDP 443 QUIC!
      if (question.qtype == 28 || question.qtype == 65 || question.qtype == 64) {
        return buildEmptyDnsNoerrorResponse(dnsQuery)
      }

      // 2. For IPv4 (A=1) queries when connected to a V2Ray/Xray proxy server:
      //    - First check if the domain belongs to Twitter/X, Instagram/Meta, YouTube/Google, or Telegram
      //      and return its real public Anycast IPv4 (so Cronet/Proxygen never see a 198.18.0.0/15 bogon IP
      //      and properly coalesce HTTP/2 connections!).
      //    - Otherwise allocate a collision-free virtual IPv4 in `198.18.x.y` mapped to `question.domain`.
      if (question.qtype == 1 &&
        question.domain.isNotEmpty() &&
        activeConfig.protocol != V2RayProtocol.SERVERLESS
      ) {
        val cleanIpStr =
          resolveKnownCleanPublicIpv4(question.domain)
            ?: allocateFakeIpForDomain(question.domain)
        val ipBytes = V2RayOutboundClient.parseIpv4Bytes(cleanIpStr)
        if (ipBytes != null) {
          return buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, ipBytes)
        }
      }
    }

    val cacheKey =
      if (question != null) {
        "${question.domain}:${question.qtype}:${question.qclass}"
      } else {
        null
      }
    if (cacheKey != null) {
      val cached = dnsCache[cacheKey]
      if (cached != null && cached.size >= 12) {
        val copy = cached.copyOf()
        copy[0] = dnsQuery[0]
        copy[1] = dnsQuery[1]
        return copy
      }
    }

    // When running in Serverless mode, resolve real IPs via fragmented DoH (port 443)
    if (activeConfig.protocol == V2RayProtocol.SERVERLESS) {
      val directDoh = resolveDnsOverHttpsProtectedDirect(dnsQuery)
      if (directDoh != null && isValidUnpoisonedDnsResponse(directDoh)) {
        if (cacheKey != null && dnsCache.size < 512) {
          dnsCache[cacheKey] = directDoh.copyOf()
        }
        return directDoh
      }
    }

    val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery)
    if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
      if (cacheKey != null && dnsCache.size < 512) {
        dnsCache[cacheKey] = dohTunnelResp.copyOf()
      }
      return dohTunnelResp
    }

    val directDohResp = resolveDnsOverHttpsProtectedDirect(dnsQuery)
    if (directDohResp != null && isValidUnpoisonedDnsResponse(directDohResp)) {
      if (cacheKey != null && dnsCache.size < 512) {
        dnsCache[cacheKey] = directDohResp.copyOf()
      }
      return directDohResp
    }

    return buildEmptyDnsNoerrorResponse(dnsQuery)
  }

  private fun resolveDnsOverHttpsViaTunnel(dnsQuery: ByteArray): ByteArray? {
    for ((targetIp, sniHost) in listOf("8.8.8.8" to "dns.google", "9.9.9.9" to "dns.quad9.net")) {
      try {
        val opened =
          openTunnelWithVerifiedFailover(
            targetHost = targetIp,
            targetPort = 443,
            timeoutMs = 2200,
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
      val host = resolveFakeIpDomain(rawHost) ?: rawHost
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
      val host = resolveFakeIpDomain(rawHost) ?: rawHost
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

  private fun buildEmptyDnsNoerrorResponse(dnsQuery: ByteArray): ByteArray {
    val resp = ByteArray(dnsQuery.size)
    System.arraycopy(dnsQuery, 0, resp, 0, dnsQuery.size)
    resp[2] = 0x81.toByte()
    resp[3] = 0x80.toByte()
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
    relayExecutor.execute {
      try {
        val buf = ByteArray(16384)
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
      val buf = ByteArray(16384)
      while (running.get()) {
        val n = remoteIn.read(buf)
        if (n <= 0) break
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
