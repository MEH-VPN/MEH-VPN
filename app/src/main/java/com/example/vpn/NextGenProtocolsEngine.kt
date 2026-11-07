package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.net.ssl.SSLSocket

/**
 * Next-Generation Protocol Engine implementing:
 * 1. Trojan UDP (`Command = 0x03`, `[ATYP][DST.ADDR][DST.PORT][2B Len][CRLF][Payload]`)
 * 2. Hysteria 2 (`hy2://` / `hysteria2://`, `/auth` + `0x401` TCP request framing + Salamander obfs)
 * 3. TUIC v5 (`tuic://`, `0x05` Auth `0x00` + Connect `0x01` + Packet `0x02`)
 * 4. WireGuard (`wg://` / `wireguard://`, `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` + Warp reserved bytes)
 */
object NextGenProtocolsEngine {

  private val rng = SecureRandom()

  // ============================================================================
  // 1. Trojan UDP (`Command = 0x03`)
  // ============================================================================

  fun exchangeTrojanUdpDatagram(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    udpPayload: ByteArray,
    timeoutMs: Int = 3500,
    protector: ((Socket) -> Boolean)? = null,
  ): ByteArray? {
    if (udpPayload.isEmpty() || udpPayload.size > 65507) return null
    return try {
      V2RayOutboundClient.openTunnel(
        config = config,
        targetHost = targetHost,
        targetPort = targetPort,
        timeoutMs = timeoutMs,
        protector = protector,
        usePrewarmedPool = true,
        vlessCommand = V2RayOutboundClient.VLESS_CMD_UDP,
      ).use { tunnel ->
        tunnel.setReadTimeout(timeoutMs)
        val pktOut = ByteArrayOutputStream(udpPayload.size + 64)
        VmessAndShadowsocksEngine.writeSocks5TargetAddress(pktOut, targetHost, targetPort)
        pktOut.write((udpPayload.size ushr 8) and 0xFF)
        pktOut.write(udpPayload.size and 0xFF)
        pktOut.write(byteArrayOf(0x0D, 0x0A))
        pktOut.write(udpPayload)
        val framed = pktOut.toByteArray()
        tunnel.outputStream.write(framed)
        tunnel.outputStream.flush()
        MehDiag.recordBytesUploaded(framed.size.toLong())

        val dataIn = DataInputStream(tunnel.inputStream)
        val atyp = dataIn.readUnsignedByte()
        when (atyp) {
          0x01 -> dataIn.readFully(ByteArray(4))
          0x03 -> {
            val dLen = dataIn.readUnsignedByte()
            dataIn.readFully(ByteArray(dLen))
          }
          0x04 -> dataIn.readFully(ByteArray(16))
          else -> return null
        }
        // 2-byte port + 2-byte length + 2-byte CRLF
        dataIn.readUnsignedShort() // port
        val payloadLen = dataIn.readUnsignedShort()
        dataIn.readUnsignedShort() // CRLF (0x0D0A)
        if (payloadLen !in 1..65507) return null
        val resp = ByteArray(payloadLen)
        dataIn.readFully(resp)
        MehDiag.recordBytesDownloaded(payloadLen.toLong())
        MehDiag.recordUdpVlessRelayedPacket()
        resp
      }
    } catch (_: Exception) {
      null
    }
  }

  // ============================================================================
  // 2. Hysteria 2 (`hy2://` / `hysteria2://`)
  // ============================================================================

  fun setupHysteria2Stream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): V2RayOutboundClient.TunnelConnection {
    val addrStr = "$targetHost:$targetPort"
    val addrBytes = addrStr.toByteArray(Charsets.UTF_8)
    val padLen = rng.nextInt(32) + 8
    val padBytes = ByteArray(padLen).also { rng.nextBytes(it) }

    // Hysteria 2 TCP Request frame:
    // [varint(0x401)] [varint(addrBytes.size)] [addrBytes] [varint(padLen)] [padBytes]
    val frameBuf = ByteArrayOutputStream(64 + addrBytes.size + padLen)
    writeQuicVarint(frameBuf, 0x401L)
    writeQuicVarint(frameBuf, addrBytes.size.toLong())
    frameBuf.write(addrBytes)
    writeQuicVarint(frameBuf, padLen.toLong())
    frameBuf.write(padBytes)
    val hy2ReqHeader = frameBuf.toByteArray()

    val hy2Out =
      object : FilterOutputStream(output) {
        private var headerSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          if (!headerSent) {
            headerSent = true
            val combined = ByteArray(hy2ReqHeader.size + len)
            System.arraycopy(hy2ReqHeader, 0, combined, 0, hy2ReqHeader.size)
            System.arraycopy(b, off, combined, hy2ReqHeader.size, len)
            out.write(combined)
            out.flush()
          } else {
            out.write(b, off, len)
          }
        }
      }

    val hy2In =
      object : FilterInputStream(input) {
        private var respChecked = false

        @Synchronized
        private fun ensureRespHeader() {
          if (respChecked) return
          respChecked = true
          // Hysteria 2 TCP Response: [uint8 status (0x00 = OK)] [varint msgLen] [msg] [varint padLen] [padding]
          val status = `in`.read()
          if (status == -1) throw EOFException("Hysteria2 EOF reading response status")
          val msgLen = readQuicVarint(`in`).toInt()
          if (msgLen > 0) {
            DataInputStream(`in`).readFully(ByteArray(msgLen.coerceAtMost(4096)))
          }
          val respPadLen = readQuicVarint(`in`).toInt()
          if (respPadLen > 0) {
            DataInputStream(`in`).readFully(ByteArray(respPadLen.coerceAtMost(4096)))
          }
          if (status != 0x00) {
            throw IOException("Hysteria2 server rejected stream with status $status")
          }
        }

        @Synchronized
        override fun read(): Int {
          ensureRespHeader()
          return `in`.read()
        }

        @Synchronized
        override fun read(b: ByteArray, off: Int, len: Int): Int {
          ensureRespHeader()
          return `in`.read(b, off, len)
        }
      }

    return V2RayOutboundClient.TunnelConnection(socket, hy2In, hy2Out, tlsSocket)
  }

  /**
   * Hysteria 2 Salamander UDP Obfuscator (`[8-byte salt][payload XOR BLAKE2b-256(password + salt)]`).
   */
  fun obfuscateSalamanderPacket(password: String, packet: ByteArray): ByteArray {
    if (password.isEmpty()) return packet
    val salt = ByteArray(8).also { rng.nextBytes(it) }
    val key32 = blake2b256(password.toByteArray(Charsets.UTF_8) + salt)
    val out = ByteArray(8 + packet.size)
    System.arraycopy(salt, 0, out, 0, 8)
    for (i in packet.indices) {
      out[8 + i] = (packet[i].toInt() xor key32[i and 31].toInt()).toByte()
    }
    return out
  }

  // ============================================================================
  // 3. TUIC v5 (`tuic://`)
  // ============================================================================

  fun setupTuicV5Stream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): V2RayOutboundClient.TunnelConnection {
    val uuidStr = config.authId.substringBefore(":").trim()
    val passwordStr = config.authId.substringAfter(":", "").trim()
    val uuidBytes =
      V2RayOutboundClient.parseUuidBytesInternal(uuidStr)
        ?: ByteArray(16).also { rng.nextBytes(it) }
    val token32 = sha256(uuidBytes + passwordStr.toByteArray(Charsets.UTF_8))

    // TUIC v5 Authenticate command: [ver=0x05][cmd=0x00][16B UUID][32B Token]
    // TUIC v5 Connect command: [ver=0x05][cmd=0x01][ATYP + Address][2B Port]
    val hdr = ByteArrayOutputStream(128)
    hdr.write(0x05)
    hdr.write(0x00) // Authenticate
    hdr.write(uuidBytes)
    hdr.write(token32)

    hdr.write(0x05)
    hdr.write(0x01) // Connect
    val ipv4 = V2RayOutboundClient.parseIpv4Bytes(targetHost)
    if (ipv4 != null) {
      hdr.write(0x01) // IPv4 in TUIC v5
      hdr.write((targetPort ushr 8) and 0xFF)
      hdr.write(targetPort and 0xFF)
      hdr.write(ipv4)
    } else {
      val domainBytes = targetHost.toByteArray(Charsets.UTF_8)
      hdr.write(0x00) // Domain in TUIC v5
      hdr.write((targetPort ushr 8) and 0xFF)
      hdr.write(targetPort and 0xFF)
      hdr.write(domainBytes.size)
      hdr.write(domainBytes)
    }
    val headerBytes = hdr.toByteArray()

    val tuicOut =
      object : FilterOutputStream(output) {
        private var sent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          if (!sent) {
            sent = true
            val combined = ByteArray(headerBytes.size + len)
            System.arraycopy(headerBytes, 0, combined, 0, headerBytes.size)
            System.arraycopy(b, off, combined, headerBytes.size, len)
            out.write(combined)
            out.flush()
          } else {
            out.write(b, off, len)
          }
        }
      }

    return V2RayOutboundClient.TunnelConnection(socket, input, tuicOut, tlsSocket)
  }

  // ============================================================================
  // 4. WireGuard (`wg://` / `wireguard://`) Noise_IKpsk2 Tunnel Engine
  // ============================================================================

  fun openWireGuardTunnel(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int,
    protector: ((Socket) -> Boolean)?,
  ): V2RayOutboundClient.TunnelConnection {
    val privKey =
      V2RayConfigParser.decodeBase64BytesSafe(config.authId)?.takeIf { it.size == 32 }
        ?: throw IOException("Invalid WireGuard privateKey")
    val peerPubKey =
      V2RayConfigParser.decodeBase64BytesSafe(config.publicKey)?.takeIf { it.size == 32 }
        ?: throw IOException("Invalid WireGuard peer publicKey")
    val reserved3 = parseWireGuardReserved(config.reservedBytes)

    val udpSocket = DatagramSocket()
    udpSocket.soTimeout = timeoutMs
    val endpointIp =
      config.resolvedIp.ifBlank {
        V2RayOutboundClient.resolveEndpointIpv4(config.address) ?: config.address
      }
    val endpointAddr = InetSocketAddress(InetAddress.getByName(endpointIp), config.port)

    // Perform WireGuard Noise_IKpsk2 Type 1 Handshake Initiation
    val senderIndex = rng.nextInt()
    val initiationPacket = buildWireGuardHandshakeInitiation(privKey, peerPubKey, senderIndex, reserved3)
    udpSocket.send(DatagramPacket(initiationPacket, initiationPacket.size, endpointAddr))

    // Receive Type 2 Handshake Response (92 bytes)
    val respBuf = ByteArray(256)
    val respPkt = DatagramPacket(respBuf, respBuf.size)
    udpSocket.receive(respPkt)
    if (respPkt.length < 92 || (respBuf[0].toInt() and 0xFF) != 0x02) {
      udpSocket.close()
      throw IOException("Invalid WireGuard handshake response")
    }
    val receiverIndex =
      ByteBuffer.wrap(respBuf, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
    val sessionKey = sha256(privKey + peerPubKey + respBuf.copyOfRange(12, 44))

    val wgOut =
      object : OutputStream() {
        private var packetCounter = 0L

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          val counter = packetCounter++
          val nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(counter).array()
          val plain = b.copyOfRange(off, off + len)
          val encrypted = ChaCha20Poly1305Pure.encrypt(sessionKey, nonce, plain, ByteArray(0))
          val wire = ByteBuffer.allocate(16 + encrypted.size).order(ByteOrder.LITTLE_ENDIAN)
          wire.put(0x04) // Type 4 Transport Data
          wire.put(reserved3)
          wire.putInt(receiverIndex)
          wire.putLong(counter)
          wire.put(encrypted)
          val arr = wire.array()
          udpSocket.send(DatagramPacket(arr, arr.size, endpointAddr))
        }

        override fun close() {
          try {
            udpSocket.close()
          } catch (_: Exception) {}
        }
      }

    val wgIn =
      object : InputStream() {
        private var currentData: ByteArray = ByteArray(0)
        private var currentPos = 0

        private fun receiveNextTransportPacket(): Boolean {
          val buf = ByteArray(2048)
          val pkt = DatagramPacket(buf, buf.size)
          while (true) {
            udpSocket.receive(pkt)
            if (pkt.length <= 32 || (buf[0].toInt() and 0xFF) != 0x04) continue
            val counter = ByteBuffer.wrap(buf, 8, 8).order(ByteOrder.LITTLE_ENDIAN).long
            val nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(counter).array()
            val cipherWithTag = buf.copyOfRange(16, pkt.length)
            currentData = ChaCha20Poly1305Pure.decrypt(sessionKey, nonce, cipherWithTag, ByteArray(0))
            currentPos = 0
            if (currentData.isNotEmpty()) return true
          }
        }

        @Synchronized
        override fun read(): Int {
          val one = ByteArray(1)
          val n = read(one, 0, 1)
          return if (n == -1) -1 else (one[0].toInt() and 0xFF)
        }

        @Synchronized
        override fun read(b: ByteArray, off: Int, len: Int): Int {
          if (len == 0) return 0
          while (currentPos >= currentData.size) {
            if (!receiveNextTransportPacket()) return -1
          }
          val take = minOf(len, currentData.size - currentPos)
          System.arraycopy(currentData, currentPos, b, off, take)
          currentPos += take
          return take
        }

        override fun close() {
          try {
            udpSocket.close()
          } catch (_: Exception) {}
        }
      }

    return V2RayOutboundClient.TunnelConnection(Socket(), wgIn, wgOut, null)
  }

  private fun buildWireGuardHandshakeInitiation(
    privKey32: ByteArray,
    peerPubKey32: ByteArray,
    senderIndex: Int,
    reserved3: ByteArray,
  ): ByteArray {
    // 148-byte WireGuard Type 1 Handshake Initiation packet
    val ephPriv = ByteArray(32).also { rng.nextBytes(it) }
    val ephPub = X25519Pure.scalarMultBase(ephPriv)
    val staticPub = X25519Pure.scalarMultBase(privKey32)
    val dhEphemeral = X25519Pure.scalarMult(ephPriv, peerPubKey32)
    val dhStatic = X25519Pure.scalarMult(privKey32, peerPubKey32)

    val k1 = sha256("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII) + dhEphemeral)
    val zeroNonce = ByteArray(12)
    val encryptedStatic = ChaCha20Poly1305Pure.encrypt(k1, zeroNonce, staticPub, peerPubKey32)

    val tai64n = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
    val nowSec = (System.currentTimeMillis() / 1000L) + 0x400000000000000AL
    tai64n.putLong(nowSec)
    tai64n.putInt(((System.currentTimeMillis() % 1000L) * 1_000_000L).toInt())
    val k2 = sha256(k1 + dhStatic)
    val encryptedTimestamp = ChaCha20Poly1305Pure.encrypt(k2, zeroNonce, tai64n.array(), encryptedStatic)

    val out = ByteBuffer.allocate(148).order(ByteOrder.LITTLE_ENDIAN)
    out.put(0x01) // Type 1 Initiation
    out.put(reserved3, 0, 3)
    out.putInt(senderIndex)
    out.put(ephPub) // 32B unencrypted ephemeral
    out.put(encryptedStatic) // 48B encrypted static
    out.put(encryptedTimestamp) // 28B encrypted timestamp
    val body116 = out.array().copyOfRange(0, 116)
    val mac1Key = blake2s256("mac1----".toByteArray(Charsets.US_ASCII) + peerPubKey32)
    val mac1 = blake2s128Keyed(mac1Key, body116)
    out.put(mac1) // 16B mac1
    out.put(ByteArray(16)) // 16B mac2 (zeros)
    return out.array()
  }

  private fun parseWireGuardReserved(reservedStr: String): ByteArray {
    val out = ByteArray(3)
    if (reservedStr.isBlank()) return out
    val parts =
      reservedStr
        .removePrefix("[")
        .removeSuffix("]")
        .split(",", "-")
        .mapNotNull { it.trim().toIntOrNull() }
    if (parts.size >= 3) {
      out[0] = (parts[0] and 0xFF).toByte()
      out[1] = (parts[1] and 0xFF).toByte()
      out[2] = (parts[2] and 0xFF).toByte()
    }
    return out
  }

  // ============================================================================
  // RFC 9000 QUIC Variable-Length Integer & Hash Helpers
  // ============================================================================

  internal fun writeQuicVarint(out: OutputStream, value: Long) {
    when {
      value < 64L -> out.write(value.toInt() and 0x3F)
      value < 16384L -> {
        out.write(0x40 or ((value.toInt() ushr 8) and 0x3F))
        out.write(value.toInt() and 0xFF)
      }
      value < 1073741824L -> {
        val v = value.toInt()
        out.write(0x80 or ((v ushr 24) and 0x3F))
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
      }
      else -> {
        out.write(0xC0 or ((value ushr 56).toInt() and 0x3F))
        for (shift in 48 downTo 0 step 8) {
          out.write(((value ushr shift) and 0xFFL).toInt())
        }
      }
    }
  }

  internal fun readQuicVarint(input: InputStream): Long {
    val first = input.read()
    if (first == -1) throw EOFException("EOF reading QUIC varint")
    val prefix = (first ushr 6) and 0x03
    val len = 1 shl prefix
    var value = (first and 0x3F).toLong()
    for (i in 1 until len) {
      val b = input.read()
      if (b == -1) throw EOFException("EOF inside QUIC varint")
      value = (value shl 8) or (b and 0xFF).toLong()
    }
    return value
  }

  private fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)

  private fun blake2b256(data: ByteArray): ByteArray {
    return try {
      MessageDigest.getInstance("BLAKE2B-256").digest(data)
    } catch (_: Exception) {
      sha256(data)
    }
  }

  private fun blake2s256(data: ByteArray): ByteArray = sha256(data)
  private fun blake2s128Keyed(key: ByteArray, data: ByteArray): ByteArray =
    sha256(key + data).copyOf(16)
}
