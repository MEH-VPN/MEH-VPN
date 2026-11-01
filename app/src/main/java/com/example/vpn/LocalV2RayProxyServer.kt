package com.example.vpn

import com.example.model.V2RayConfig
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Local multi-protocol proxy server supporting:
 * - SOCKS5 CONNECT (0x01) for all TCP streams from tun2socks
 * - SOCKS5 UDP ASSOCIATE (0x03) for UDP / DNS queries from tun2socks (resolving port 53 DNS
 *   over V2Ray TCP tunnel to 1.1.1.1:53 / 8.8.8.8:53 to prevent DNS poisoning)
 * - HTTP/HTTPS CONNECT proxy
 */
class LocalV2RayProxyServer(
  private val config: V2RayConfig,
  private val protector: (Socket) -> Boolean,
  private val udpProtector: (DatagramSocket) -> Boolean = { true },
) {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var serverSocket: ServerSocket? = null
  private var udpRelaySocket: DatagramSocket? = null
  private var acceptJob: Job? = null
  private var udpRelayJob: Job? = null

  var listenPort: Int = 0
    private set

  var udpListenPort: Int = 0
    private set

  fun start(): Int {
    val localhost = InetAddress.getByName("127.0.0.1")
    val server = ServerSocket(0, 256, localhost)
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
            client.soTimeout = 60_000
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
    scope.cancel()
  }

  private fun handleClient(clientSocket: Socket) {
    try {
      clientSocket.use { client ->
        val clientIn = client.getInputStream()
        val clientOut = client.getOutputStream()

        val firstByte = clientIn.read()
        if (firstByte == -1) return

        if (firstByte == 0x05) {
          handleSocks5Client(clientIn, clientOut)
        } else {
          handleHttpProxyClient(firstByte.toByte(), clientIn, clientOut)
        }
      }
    } catch (_: Exception) {}
  }

  private fun handleSocks5Client(clientIn: InputStream, clientOut: OutputStream) {
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
        // TCP CONNECT
        V2RayOutboundClient.openTunnel(
          config = config,
          targetHost = targetHost,
          targetPort = targetPort,
          protector = protector,
        ).use { tunnel ->
          clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
          clientOut.flush()
          relayStreams(clientIn, clientOut, tunnel.inputStream, tunnel.outputStream)
        }
      }
      0x03 -> {
        // UDP ASSOCIATE: return 127.0.0.1:udpListenPort and hold TCP control channel open
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
    if (frag != 0) return // Fragmented UDP not used
    val atyp = packet[3].toInt() and 0xFF

    var offset = 4
    val dstHost: String =
      when (atyp) {
        0x01 -> {
          if (packet.size < offset + 6) return
          val ip =
            "${packet[offset].toInt() and 0xFF}.${packet[offset + 1].toInt() and 0xFF}.${packet[offset + 2].toInt() and 0xFF}.${packet[offset + 3].toInt() and 0xFF}"
          offset += 4
          ip
        }
        0x03 -> {
          val len = packet[offset].toInt() and 0xFF
          offset += 1
          if (packet.size < offset + len + 2) return
          val domain = String(packet, offset, len, Charsets.UTF_8)
          offset += len
          domain
        }
        0x04 -> {
          if (packet.size < offset + 18) return
          val ipv6 = packet.copyOfRange(offset, offset + 16)
          offset += 16
          InetAddress.getByAddress(ipv6).hostAddress ?: return
        }
        else -> return
      }

    val dstPort = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    offset += 2

    val socksUdpHeader = packet.copyOfRange(0, offset)
    val udpPayload = packet.copyOfRange(offset, packet.size)
    if (udpPayload.isEmpty()) return

    val responsePayload: ByteArray =
      if (dstPort == 53) {
        resolveDnsOverV2Ray(udpPayload) ?: return
      } else {
        forwardProtectedUdp(dstHost, dstPort, udpPayload) ?: return
      }

    val replyBytes = ByteArray(socksUdpHeader.size + responsePayload.size)
    System.arraycopy(socksUdpHeader, 0, replyBytes, 0, socksUdpHeader.size)
    System.arraycopy(responsePayload, 0, replyBytes, socksUdpHeader.size, responsePayload.size)

    try {
      udpServer.send(DatagramPacket(replyBytes, replyBytes.size, clientAddr, clientPort))
    } catch (_: Exception) {}
  }

  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    // 1. Primary: Resolve DNS over TCP through the encrypted V2Ray tunnel (1.1.1.1:53 or 8.8.8.8:53)
    for (dnsServer in listOf("1.1.1.1", "8.8.8.8")) {
      try {
        V2RayOutboundClient.openTunnel(
          config = config,
          targetHost = dnsServer,
          targetPort = 53,
          timeoutMs = 3000,
          protector = protector,
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
            return resp
          }
        }
      } catch (_: Exception) {}
    }

    // 2. Fallback: Protected UDP DNS
    return forwardProtectedUdp("8.8.8.8", 53, dnsQuery)
  }

  private fun forwardProtectedUdp(host: String, port: Int, payload: ByteArray): ByteArray? {
    return try {
      DatagramSocket().use { sock ->
        udpProtector(sock)
        sock.soTimeout = 2500
        val addr = InetAddress.getByName(host)
        sock.send(DatagramPacket(payload, payload.size, addr, port))
        val recvBuf = ByteArray(2048)
        val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
        sock.receive(recvPkt)
        recvBuf.copyOfRange(0, recvPkt.length)
      }
    } catch (_: Exception) {
      null
    }
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

      V2RayOutboundClient.openTunnel(
        config = config,
        targetHost = host,
        targetPort = port,
        protector = protector,
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

      V2RayOutboundClient.openTunnel(
        config = config,
        targetHost = host,
        targetPort = port,
        protector = protector,
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
}
