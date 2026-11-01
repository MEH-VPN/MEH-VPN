package com.example.vpn

import com.example.model.V2RayConfig
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
import java.net.SocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Local multi-protocol proxy server supporting:
 * - SOCKS5 CONNECT (0x01) for all TCP streams from tun2socks with automatic multi-server failover
 * - SOCKS5 UDP ASSOCIATE (0x03) for UDP / DNS queries from tun2socks:
 *   - Resolves port 53 DNS over V2Ray TCP (8.8.8.8:53 / 9.9.9.9:53) or encrypted DoH (8.8.8.8:443)
 *     with an in-memory cache and anti-poisoning validation
 *   - Drops non-53 UDP (e.g. UDP 443 QUIC) so Chrome/YouTube/Instagram immediately fall back to TCP 443 over V2Ray
 * - HTTP/HTTPS CONNECT proxy
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

  private val serverPool: List<V2RayConfig> = configs.ifEmpty {
    throw IllegalArgumentException("At least one V2RayConfig is required")
  }
  private val activeConfigIndex = AtomicInteger(0)
  private val dnsCache = ConcurrentHashMap<String, ByteArray>()

  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var serverSocket: ServerSocket? = null
  private var udpRelaySocket: DatagramSocket? = null
  private var acceptJob: Job? = null
  private var udpRelayJob: Job? = null

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

    acceptJob =
      scope.launch {
        while (isActive && !server.isClosed) {
          try {
            val client = server.accept()
            client.tcpNoDelay = true
            client.soTimeout = 120_000
            launch { handleClient(client) }
          } catch (_: Exception) {
            if (server.isClosed) break
          }
        }
      }

    udpRelayJob =
      scope.launch {
        val buf = ByteArray(4096)
        while (isActive && !udpServer.isClosed) {
          try {
            val pkt = DatagramPacket(buf, buf.size)
            udpServer.receive(pkt)
            val dataCopy = buf.copyOfRange(0, pkt.length)
            val clientAddr = pkt.address
            val clientPort = pkt.port
            launch {
              handleSocks5UdpDatagram(udpServer, dataCopy, clientAddr, clientPort)
            }
          } catch (_: Exception) {
            if (udpServer.isClosed) break
          }
        }
      }

    return listenPort
  }

  fun stop() {
    acceptJob?.cancel()
    udpRelayJob?.cancel()
    try {
      serverSocket?.close()
    } catch (_: Exception) {}
    try {
      udpRelaySocket?.close()
    } catch (_: Exception) {}
    serverSocket = null
    udpRelaySocket = null
    dnsCache.clear()
    scope.cancel()
  }

  private fun openTunnelWithFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 7000,
  ): V2RayOutboundClient.TunnelConnection {
    val poolSize = serverPool.size
    val startIdx = activeConfigIndex.get().coerceIn(0, poolSize - 1)
    var lastError: Exception? = null

    for (offset in 0 until poolSize) {
      val idx = (startIdx + offset) % poolSize
      val candidate = serverPool[idx]
      try {
        val conn =
          V2RayOutboundClient.openTunnel(
            config = candidate,
            targetHost = targetHost,
            targetPort = targetPort,
            timeoutMs = if (offset == 0) timeoutMs else 4500,
            protector = protector,
          )
        if (offset > 0) {
          activeConfigIndex.set(idx)
        }
        return conn
      } catch (e: Exception) {
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
          handleHttpProxyClient(firstByte.toByte(), clientIn, clientOut)
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

    val targetHost: String =
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
        // TCP CONNECT with automatic failover
        val tunnel =
          try {
            openTunnelWithFailover(
              targetHost = targetHost,
              targetPort = targetPort,
            )
          } catch (_: Exception) {
            try {
              clientOut.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
              clientOut.flush()
            } catch (_: Exception) {}
            return
          }

        tunnel.use { activeTunnel ->
          clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
          clientOut.flush()
          relayStreams(clientIn, clientOut, activeTunnel.inputStream, activeTunnel.outputStream)
        }
      }
      0x03 -> {
        // UDP ASSOCIATE: return 127.0.0.1:udpListenPort and hold TCP control channel open indefinitely
        clientSocket.soTimeout = 0
        val pHigh = ((udpListenPort ushr 8) and 0xFF).toByte()
        val pLow = (udpListenPort and 0xFF).toByte()
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pHigh, pLow))
        clientOut.flush()
        while (clientIn.read() != -1) {
          // Wait until client closes TCP control connection
        }
      }
      else -> {
        clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        clientOut.flush()
      }
    }
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

  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.size < 12) return null
    val cacheKey = extractDnsCacheKey(dnsQuery)
    if (cacheKey != null) {
      val cached = dnsCache[cacheKey]
      if (cached != null && cached.size >= 12) {
        val copy = cached.copyOf()
        copy[0] = dnsQuery[0]
        copy[1] = dnsQuery[1]
        return copy
      }
    }

    // 1. Primary: Resolve DNS over TCP through the V2Ray tunnel (8.8.8.8:53 or 9.9.9.9:53)
    for (dnsServer in listOf("8.8.8.8", "9.9.9.9")) {
      try {
        openTunnelWithFailover(
          targetHost = dnsServer,
          targetPort = 53,
          timeoutMs = 2200,
        ).use { tunnel ->
          val framed = ByteArray(dnsQuery.size + 2)
          framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
          framed[1] = (dnsQuery.size and 0xFF).toByte()
          System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)

          tunnel.outputStream.write(framed)
          tunnel.outputStream.flush()

          val dataIn = DataInputStream(tunnel.inputStream)
          val respLen = dataIn.readUnsignedShort()
          if (respLen in 12..4096) {
            val resp = ByteArray(respLen)
            dataIn.readFully(resp)
            if (isValidUnpoisonedDnsResponse(resp)) {
              if (cacheKey != null && dnsCache.size < 512) {
                dnsCache[cacheKey] = resp.copyOf()
              }
              return resp
            }
          }
        }
      } catch (_: Exception) {}
    }

    // 2. Secondary: Resolve DNS over HTTPS (DoH port 443) through the V2Ray tunnel
    //    (Handles Cloudflare Worker VLESS/Trojan nodes that block port 53)
    val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery)
    if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
      if (cacheKey != null && dnsCache.size < 512) {
        dnsCache[cacheKey] = dohTunnelResp.copyOf()
      }
      return dohTunnelResp
    }

    // 3. Final fallback: Direct encrypted DoH (port 443 TLS) via protected socket
    val directDohResp = resolveDnsOverHttpsProtectedDirect(dnsQuery)
    if (directDohResp != null && isValidUnpoisonedDnsResponse(directDohResp)) {
      if (cacheKey != null && dnsCache.size < 512) {
        dnsCache[cacheKey] = directDohResp.copyOf()
      }
      return directDohResp
    }

    return null
  }

  private fun resolveDnsOverHttpsViaTunnel(dnsQuery: ByteArray): ByteArray? {
    return try {
      openTunnelWithFailover(
        targetHost = "8.8.8.8",
        targetPort = 443,
        timeoutMs = 3000,
      ).use { tunnel ->
        val adapter = ProxyStreamSocketAdapter(tunnel.inputStream, tunnel.outputStream)
        val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val sslSocket = sslFactory.createSocket(adapter, "dns.google", 443, true) as SSLSocket
        sslSocket.use { tls ->
          try {
            val params = tls.sslParameters
            params.serverNames = listOf(SNIHostName("dns.google"))
            tls.sslParameters = params
          } catch (_: Throwable) {}
          tls.startHandshake()
          executeDohPost(tls.inputStream, tls.outputStream, "dns.google", dnsQuery)
        }
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun resolveDnsOverHttpsProtectedDirect(dnsQuery: ByteArray): ByteArray? {
    for (dohIp in listOf(byteArrayOf(8, 8, 8, 8), byteArrayOf(1, 1, 1, 1))) {
      try {
        Socket().use { raw ->
          raw.reuseAddress
          protector(raw)
          raw.soTimeout = 2500
          raw.connect(InetSocketAddress(InetAddress.getByAddress(dohIp), 443), 2500)
          val sniHost = if (dohIp[0].toInt() == 8) "dns.google" else "cloudflare-dns.com"
          val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
          val sslSocket = sslFactory.createSocket(raw, sniHost, 443, true) as SSLSocket
          sslSocket.use { tls ->
            try {
              val params = tls.sslParameters
              params.serverNames = listOf(SNIHostName(sniHost))
              tls.sslParameters = params
            } catch (_: Throwable) {}
            tls.startHandshake()
            val resp = executeDohPost(tls.inputStream, tls.outputStream, sniHost, dnsQuery)
            if (resp != null) return resp
          }
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

  private fun extractDnsCacheKey(dnsQuery: ByteArray): String? {
    if (dnsQuery.size < 17) return null
    var offset = 12
    val sb = StringBuilder()
    while (offset < dnsQuery.size) {
      val len = dnsQuery[offset].toInt() and 0xFF
      offset += 1
      if (len == 0) break
      if (len >= 0xC0 || offset + len > dnsQuery.size) return null
      sb.append(String(dnsQuery, offset, len, Charsets.US_ASCII).lowercase()).append('.')
      offset += len
    }
    if (offset + 4 > dnsQuery.size) return null
    val qtype = ((dnsQuery[offset].toInt() and 0xFF) shl 8) or (dnsQuery[offset + 1].toInt() and 0xFF)
    val qclass = ((dnsQuery[offset + 2].toInt() and 0xFF) shl 8) or (dnsQuery[offset + 3].toInt() and 0xFF)
    return "$sb:$qtype:$qclass"
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
      val host = target.substringBeforeLast(":").trim()
      val port = target.substringAfterLast(":", "443").toIntOrNull() ?: 443
      if (host.isEmpty()) return

      openTunnelWithFailover(
        targetHost = host,
        targetPort = port,
      ).use { tunnel ->
        val established = "HTTP/1.1 200 Connection Established\r\n\r\n"
        clientOut.write(established.toByteArray(Charsets.US_ASCII))
        clientOut.flush()
        relayStreams(clientIn, clientOut, tunnel.inputStream, tunnel.outputStream)
      }
    } else {
      val withoutHttp = target.removePrefix("http://").removePrefix("https://")
      val authority = withoutHttp.substringBefore("/")
      val path = "/" + withoutHttp.substringAfter("/", "")
      val host = authority.substringBeforeLast(":").trim()
      val port =
        if (authority.contains(":")) {
          authority.substringAfterLast(":").toIntOrNull() ?: 80
        } else {
          80
        }
      if (host.isEmpty()) return

      val rewrittenHeader =
        headerStr.replaceFirst("$method $target ", "$method $path ")

      openTunnelWithFailover(
        targetHost = host,
        targetPort = port,
      ).use { tunnel ->
        tunnel.outputStream.write(rewrittenHeader.toByteArray(Charsets.ISO_8859_1))
        tunnel.outputStream.flush()
        relayStreams(clientIn, clientOut, tunnel.inputStream, tunnel.outputStream)
      }
    }
  }

  private fun relayStreams(
    clientIn: InputStream,
    clientOut: OutputStream,
    remoteIn: InputStream,
    remoteOut: OutputStream,
  ) {
    val upstreamJob =
      scope.launch {
        try {
          val buf = ByteArray(16384)
          while (isActive) {
            val n = clientIn.read(buf)
            if (n <= 0) break
            remoteOut.write(buf, 0, n)
            remoteOut.flush()
          }
        } catch (_: Exception) {}
      }

    try {
      val buf = ByteArray(16384)
      while (true) {
        val n = remoteIn.read(buf)
        if (n <= 0) break
        clientOut.write(buf, 0, n)
        clientOut.flush()
      }
    } catch (_: Exception) {
    } finally {
      upstreamJob.cancel()
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

  private class ProxyStreamSocketAdapter(
    private val inStream: InputStream,
    private val outStream: OutputStream,
  ) : Socket() {
    @Volatile private var closed = false
    override fun isConnected(): Boolean = !closed
    override fun isBound(): Boolean = true
    override fun isClosed(): Boolean = closed
    override fun getInputStream(): InputStream = inStream
    override fun getOutputStream(): OutputStream = outStream
    override fun getInetAddress(): InetAddress = InetAddress.getLoopbackAddress()
    override fun getLocalAddress(): InetAddress = InetAddress.getLoopbackAddress()
    override fun getPort(): Int = 443
    override fun getLocalPort(): Int = 54321
    override fun getRemoteSocketAddress(): SocketAddress =
      InetSocketAddress(InetAddress.getLoopbackAddress(), 443)
    override fun setSoTimeout(timeout: Int) {}
    override fun getSoTimeout(): Int = 0
    override fun setTcpNoDelay(on: Boolean) {}
    override fun getTcpNoDelay(): Boolean = true
    override fun setKeepAlive(on: Boolean) {}
    override fun getKeepAlive(): Boolean = true
    @Synchronized
    override fun close() {
      closed = true
    }
  }
}
