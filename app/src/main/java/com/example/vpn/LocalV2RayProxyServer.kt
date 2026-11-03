package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
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
 * 2. Instant FakeDNS (`198.18.0.0/15`, RFC 2544 virtual subnet) + `QTYPE=65` (HTTPS/QUIC) suppression:
 *    - Resolves `A` queries in 0.2ms to deterministic virtual IPs (`198.18.x.y`) and maps them back
 *      to the exact domain name when `tun2socks` opens a SOCKS5 TCP connection.
 *    - Suppresses `AAAA` (`QTYPE=28`) and `HTTPS/SVCB` (`QTYPE=65/64`) in 0.1ms so apps never stall
 *      on IPv6 or UDP 443 QUIC probes.
 * 3. TLS `ClientHello` SNI & HTTP `Host:` Sniffing (`destOverride: ["http", "tls"]`):
 *    - Inspects the first client packet and overrides cached/poisoned IPs (`10.10.34.x`) or raw
 *      Cloudflare edge IPs (`104.16.x.y` rejected by CF Workers) with the real domain name!
 * 4. Synchronous first-packet VLESS/Trojan handshake with automatic multi-server failover.
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
    private val fakeIpCounter = AtomicInteger(10)
    private val domainToFakeIp = ConcurrentHashMap<String, String>()
    private val fakeIpToDomain = ConcurrentHashMap<String, String>()

    /**
     * Allocates or retrieves a deterministic virtual IPv4 address in the RFC 2544 benchmark
     * range `198.18.0.10 .. 198.19.255.250` for [domain].
     */
    fun allocateFakeIpForDomain(domain: String): String {
      val normalized = domain.trim().trimEnd('.').lowercase()
      domainToFakeIp[normalized]?.let { return it }

      val idx = (fakeIpCounter.getAndIncrement() and 0x1FFFF).coerceAtLeast(10)
      val thirdOctet = (idx ushr 8) and 0x01 // 0 or 1 -> 198.18.x.y or 198.19.x.y
      val fourthHigh = (idx ushr 8) and 0xFF
      val fourthLow = (idx and 0xFF).coerceIn(2, 254)
      val secondOctet = 18 + thirdOctet
      val fakeIp = "198.$secondOctet.$fourthHigh.$fourthLow"

      val existing = domainToFakeIp.putIfAbsent(normalized, fakeIp)
      val finalIp = existing ?: fakeIp
      fakeIpToDomain[finalIp] = normalized
      return finalIp
    }

    fun resolveFakeIpDomain(hostOrIp: String): String? {
      return fakeIpToDomain[hostOrIp.trim()]
    }

    fun isFakeIpAddress(hostOrIp: String): Boolean {
      val trimmed = hostOrIp.trim()
      return trimmed.startsWith("198.18.") || trimmed.startsWith("198.19.")
    }
  }

  private val serverPool: List<V2RayConfig> =
    configs.ifEmpty {
      throw IllegalArgumentException("At least one V2RayConfig is required")
    }
  private val activeConfigIndex = AtomicInteger(0)
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
          client.soTimeout = 15_000
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

  private fun openTunnelWithFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 6500,
    initialPayload: ByteArray? = null,
    initialPayloadLen: Int = 0,
  ): V2RayOutboundClient.TunnelConnection {
    val poolSize = serverPool.size
    val startIdx = activeConfigIndex.get().coerceIn(0, poolSize - 1)
    var lastError: Exception? = null

    for (offset in 0 until poolSize) {
      val idx = (startIdx + offset) % poolSize
      val candidate = serverPool[idx]
      var conn: V2RayOutboundClient.TunnelConnection? = null
      try {
        conn =
          V2RayOutboundClient.openTunnel(
            config = candidate,
            targetHost = targetHost,
            targetPort = targetPort,
            timeoutMs = if (offset == 0) timeoutMs else 4500,
            protector = protector,
          )
        if (initialPayload != null && initialPayloadLen > 0) {
          conn.outputStream.write(initialPayload, 0, initialPayloadLen)
          conn.outputStream.flush()
        }
        if (offset > 0) {
          activeConfigIndex.set(idx)
        }
        return conn
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
        // 1. If targetPort is 53 (TCP DNS query through tun2socks), handle or forward to 8.8.8.8:53
        var effectiveHost =
          if (targetPort == 53 && isFakeIpAddress(rawTargetHost)) {
            "8.8.8.8"
          } else {
            resolveFakeIpDomain(rawTargetHost) ?: rawTargetHost
          }

        // 2. Acknowledge SOCKS5 CONNECT so the client app immediately sends its first packet
        //    (e.g. TLS ClientHello or HTTP request), allowing us to sniff SNI / Host header
        //    and send the VLESS/Trojan header + first payload together synchronously!
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
        clientOut.flush()

        val firstBuffer = ByteArray(16384)
        val firstLen =
          try {
            clientSocket.soTimeout = 1500
            val n = clientIn.read(firstBuffer)
            if (n == -1) return
            n
          } catch (_: SocketTimeoutException) {
            0
          }

        // 3. Sniff TLS ClientHello SNI or HTTP Host header (`destOverride: ["http", "tls"]`)
        //    Whenever the app connected to a raw IP (such as a cached ISP-poisoned 10.10.34.x IP
        //    or a Cloudflare IP 104.16.x.y that Cloudflare Workers block), override with the sniffed domain!
        if (firstLen > 0) {
          val sniffedDomain =
            GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
              ?: extractHttpHostHeader(firstBuffer, firstLen)
          if (!sniffedDomain.isNullOrBlank()) {
            val isIpTarget =
              V2RayOutboundClient.parseIpv4Bytes(effectiveHost) != null ||
                effectiveHost.contains(":") ||
                isFakeIpAddress(effectiveHost)
            if (isIpTarget) {
              effectiveHost = sniffedDomain
            }
          }
        }

        // If the destination is still a poisoned 10.x.x.x IP with no SNI, drop fast so the app retries DNS
        val ipv4Target = V2RayOutboundClient.parseIpv4Bytes(effectiveHost)
        if (ipv4Target != null && (ipv4Target[0].toInt() and 0xFF) == 10) {
          return
        }

        clientSocket.soTimeout = 0

        val tunnel =
          try {
            openTunnelWithFailover(
              targetHost = effectiveHost,
              targetPort = targetPort,
              initialPayload = firstBuffer,
              initialPayloadLen = firstLen,
            )
          } catch (_: Exception) {
            return
          }

        tunnel.use { activeTunnel ->
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
        // UDP ASSOCIATE: return 127.0.0.1:udpListenPort and keep control socket open with an 8s timeout
        // so ephemeral DNS UDP control sockets from tun2socks never leak threads.
        clientSocket.soTimeout = 8_000
        val pHigh = ((udpListenPort ushr 8) and 0xFF).toByte()
        val pLow = (udpListenPort and 0xFF).toByte()
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pHigh, pLow))
        clientOut.flush()
        try {
          while (running.get() && clientIn.read() != -1) {
            // Wait until client closes TCP control connection or 8s idle timeout expires
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
   * Builds an instant RFC 1035 DNS `A` response for [dnsQuery] returning [ipv4Bytes] with a 60s TTL.
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
    // TTL = 60 seconds (0x0000003C)
    finalOut.write(byteArrayOf(0x00, 0x00, 0x00, 0x3C))
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
      //    so Android 9 and Chrome/Instagram/YouTube never stall on IPv6 or UDP 443 QUIC!
      if (question.qtype == 28 || question.qtype == 65 || question.qtype == 64) {
        return buildEmptyDnsNoerrorResponse(dnsQuery)
      }

      // 2. Instant FakeDNS for all IPv4 (A=1) queries when connected to a V2Ray/Xray proxy server!
      //    Returns a virtual IP (198.18.x.y) in 0.2ms and resolves the domain remotely on the V2Ray server.
      if (question.qtype == 1 &&
        question.domain.isNotEmpty() &&
        activeConfig.protocol != V2RayProtocol.SERVERLESS
      ) {
        val fakeIpStr = allocateFakeIpForDomain(question.domain)
        val fakeIpBytes = V2RayOutboundClient.parseIpv4Bytes(fakeIpStr)
        if (fakeIpBytes != null) {
          return buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, fakeIpBytes)
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

    // Primary remote DNS: Resolve DNS over HTTPS (DoH port 443) to dns.google (8.8.8.8) first
    // (since Cloudflare Workers block 1.1.1.1!).
    val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery)
    if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
      if (cacheKey != null && dnsCache.size < 512) {
        dnsCache[cacheKey] = dohTunnelResp.copyOf()
      }
      return dohTunnelResp
    }

    // Secondary fallback: Direct encrypted DoH (port 443 TLS) via protected socket + SSLEngine
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
    // Always query 8.8.8.8 (dns.google) FIRST because Cloudflare Workers reject connections to 1.1.1.1!
    for ((targetIp, sniHost) in listOf("8.8.8.8" to "dns.google", "9.9.9.9" to "dns.quad9.net")) {
      try {
        openTunnelWithFailover(
          targetHost = targetIp,
          targetPort = 443,
          timeoutMs = 2200,
        ).use { tunnel ->
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
        // Reject ISP DNS poisoning / sinkhole IPs (10.10.34.x, 127.x.x.x, 0.0.0.0)
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

      val firstBuffer = ByteArray(16384)
      val firstLen =
        try {
          clientSocket.soTimeout = 1500
          val n = clientIn.read(firstBuffer)
          if (n == -1) return
          n
        } catch (_: SocketTimeoutException) {
          0
        }

      var effectiveHost = host
      if (firstLen > 0) {
        val sniffed = GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
        if (!sniffed.isNullOrBlank() && V2RayOutboundClient.parseIpv4Bytes(effectiveHost) != null) {
          effectiveHost = sniffed
        }
      }
      clientSocket.soTimeout = 0

      openTunnelWithFailover(
        targetHost = effectiveHost,
        targetPort = port,
        initialPayload = firstBuffer,
        initialPayloadLen = firstLen,
      ).use { tunnel ->
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

      openTunnelWithFailover(
        targetHost = host,
        targetPort = port,
        initialPayload = rewrittenBytes,
        initialPayloadLen = rewrittenBytes.size,
      ).use { tunnel ->
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
    // Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0 (No error) -> 0x8180
    resp[2] = 0x81.toByte()
    resp[3] = 0x80.toByte()
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
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
      } finally {
        try {
          tunnelConnection?.close()
        } catch (_: Exception) {}
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
