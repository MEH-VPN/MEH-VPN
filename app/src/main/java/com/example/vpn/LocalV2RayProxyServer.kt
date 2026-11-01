package com.example.vpn

import com.example.model.V2RayConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Local multi-protocol proxy server (supports both HTTP/HTTPS CONNECT and SOCKS5 on the same port!)
 * that forwards all connections through [V2RayOutboundClient] over VPN-protected sockets.
 */
class LocalV2RayProxyServer(
  private val config: V2RayConfig,
  private val protector: (Socket) -> Boolean,
) {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var serverSocket: ServerSocket? = null
  private var acceptJob: Job? = null

  var listenPort: Int = 0
    private set

  fun start(): Int {
    val server = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
    serverSocket = server
    listenPort = server.localPort

    acceptJob =
      scope.launch {
        while (isActive && !server.isClosed) {
          try {
            val client = server.accept()
            client.tcpNoDelay = true
            client.soTimeout = 30_000
            launch { handleClient(client) }
          } catch (_: Exception) {
            if (server.isClosed) break
          }
        }
      }
    return listenPort
  }

  fun stop() {
    acceptJob?.cancel()
    try {
      serverSocket?.close()
    } catch (_: Exception) {}
    serverSocket = null
    scope.cancel()
  }

  private fun handleClient(clientSocket: Socket) {
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
  }

  private fun handleSocks5Client(clientIn: InputStream, clientOut: OutputStream) {
    val nMethods = clientIn.read()
    if (nMethods < 0) return
    val methods = ByteArray(nMethods)
    readExact(clientIn, methods)

    // Reply: SOCKS5, NO AUTH (0x00)
    clientOut.write(byteArrayOf(0x05, 0x00))
    clientOut.flush()

    val reqHeader = ByteArray(4)
    if (!readExact(clientIn, reqHeader)) return
    val cmd = reqHeader[1].toInt() and 0xFF
    val atyp = reqHeader[3].toInt() and 0xFF

    if (cmd != 0x01) {
      // Command not supported
      clientOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
      clientOut.flush()
      return
    }

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

    V2RayOutboundClient.openTunnel(
      config = config,
      targetHost = targetHost,
      targetPort = targetPort,
      protector = protector,
    ).use { tunnel ->
      // SOCKS5 Success reply
      clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
      clientOut.flush()
      relayStreams(clientIn, clientOut, tunnel.inputStream, tunnel.outputStream)
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
      // Plain HTTP proxy request (e.g., GET http://example.com/path HTTP/1.1)
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
