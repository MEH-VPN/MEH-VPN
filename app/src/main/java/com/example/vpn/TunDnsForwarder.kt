package com.example.vpn

import android.os.ParcelFileDescriptor
import com.example.model.V2RayConfig
import java.io.DataInputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Reads IPv4 UDP DNS queries (port 53) from the Android VpnService TUN descriptor,
 * resolves them through the V2Ray tunnel (or protected socket fallback), and writes
 * valid IPv4 + UDP DNS response packets back to the TUN interface.
 */
class TunDnsForwarder(
  private val tunPfd: ParcelFileDescriptor,
  private val config: V2RayConfig,
  private val protector: (Socket) -> Boolean,
  private val udpProtector: (DatagramSocket) -> Boolean,
) {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var readerJob: Job? = null

  fun start() {
    val inputStream = FileInputStream(tunPfd.fileDescriptor)
    val outputStream = FileOutputStream(tunPfd.fileDescriptor)
    val writeLock = Any()

    readerJob =
      scope.launch {
        val packetBuf = ByteArray(32767)
        while (isActive) {
          val length =
            try {
              inputStream.read(packetBuf)
            } catch (_: Exception) {
              break
            }
          if (length <= 28) continue

          val version = (packetBuf[0].toInt() ushr 4) and 0x0F
          if (version != 4) continue

          val ihl = (packetBuf[0].toInt() and 0x0F) * 4
          if (length < ihl + 8) continue

          val protocol = packetBuf[9].toInt() and 0xFF
          if (protocol != 17) continue // Only UDP (17)

          val dstPort =
            ((packetBuf[ihl + 2].toInt() and 0xFF) shl 8) or
              (packetBuf[ihl + 3].toInt() and 0xFF)
          if (dstPort != 53) continue

          val requestCopy = packetBuf.copyOfRange(0, length)
          launch {
            handleDnsPacket(requestCopy, ihl, outputStream, writeLock)
          }
        }
      }
  }

  fun stop() {
    readerJob?.cancel()
    scope.cancel()
  }

  private fun handleDnsPacket(
    packet: ByteArray,
    ihl: Int,
    tunOut: FileOutputStream,
    writeLock: Any,
  ) {
    try {
      val udpHeaderOffset = ihl
      val dnsPayloadOffset = udpHeaderOffset + 8
      val dnsPayloadLen = packet.size - dnsPayloadOffset
      if (dnsPayloadLen <= 12) return

      val dnsQuery = packet.copyOfRange(dnsPayloadOffset, packet.size)
      val dnsResponse =
        if (isAaaaQuery(dnsQuery)) {
          buildSyntheticNoDataResponse(dnsQuery)
        } else {
          resolveDnsViaV2RayOrProtected(dnsQuery) ?: return
        }

      val responsePacket = buildIpv4UdpReply(packet, ihl, dnsResponse)
      synchronized(writeLock) {
        tunOut.write(responsePacket)
        tunOut.flush()
      }
    } catch (_: Exception) {}
  }

  private fun resolveDnsViaV2RayOrProtected(dnsQuery: ByteArray): ByteArray? {
    // 1. Primary: DNS-over-TCP through V2Ray outbound tunnel to 1.1.1.1:53
    queryDnsOverTcpThroughV2Ray(dnsQuery, "1.1.1.1")?.let { return it }

    // 2. Secondary fallback: DNS-over-TCP through V2Ray outbound tunnel to 8.8.8.8:53
    queryDnsOverTcpThroughV2Ray(dnsQuery, "8.8.8.8")?.let { return it }

    // 3. Last-resort fallback: Protected UDP socket to 8.8.8.8:53
    return try {
      DatagramSocket().use { udpSocket ->
        udpProtector(udpSocket)
        udpSocket.soTimeout = 2000
        val target = InetAddress.getByName("8.8.8.8")
        udpSocket.send(DatagramPacket(dnsQuery, dnsQuery.size, target, 53))
        val buf = ByteArray(1500)
        val recv = DatagramPacket(buf, buf.size)
        udpSocket.receive(recv)
        buf.copyOfRange(0, recv.length)
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun queryDnsOverTcpThroughV2Ray(dnsQuery: ByteArray, dnsHost: String): ByteArray? {
    return try {
      V2RayOutboundClient.openTunnel(
        config = config,
        targetHost = dnsHost,
        targetPort = 53,
        timeoutMs = 2500,
        protector = protector,
      ).use { tunnel ->
        val framedQuery = ByteArray(dnsQuery.size + 2)
        framedQuery[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
        framedQuery[1] = (dnsQuery.size and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, framedQuery, 2, dnsQuery.size)

        tunnel.outputStream.write(framedQuery)
        tunnel.outputStream.flush()

        val dataIn = DataInputStream(tunnel.inputStream)
        val respLen = dataIn.readUnsignedShort()
        if (respLen in 12..4096) {
          val resp = ByteArray(respLen)
          dataIn.readFully(resp)
          resp
        } else {
          null
        }
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun isAaaaQuery(dnsQuery: ByteArray): Boolean {
    if (dnsQuery.size < 16) return false
    val qdCount = ((dnsQuery[4].toInt() and 0xFF) shl 8) or (dnsQuery[5].toInt() and 0xFF)
    if (qdCount < 1) return false
    var offset = 12
    while (offset < dnsQuery.size) {
      val len = dnsQuery[offset].toInt() and 0xFF
      if (len == 0) {
        offset++ // Skip 0x00 terminating root label
        break
      }
      offset += 1 + len
    }
    if (offset + 4 <= dnsQuery.size) {
      val qType = ((dnsQuery[offset].toInt() and 0xFF) shl 8) or (dnsQuery[offset + 1].toInt() and 0xFF)
      return qType == 28 // 28 = AAAA (IPv6)
    }
    return false
  }

  private fun buildSyntheticNoDataResponse(dnsQuery: ByteArray): ByteArray {
    var questionEnd = 12
    while (questionEnd < dnsQuery.size) {
      val len = dnsQuery[questionEnd].toInt() and 0xFF
      if (len == 0) {
        questionEnd += 5 // 1 byte (0x00) + 2 bytes QTYPE + 2 bytes QCLASS
        break
      }
      questionEnd += 1 + len
    }
    val safeEnd = questionEnd.coerceAtMost(dnsQuery.size)
    val resp = ByteArray(safeEnd)
    System.arraycopy(dnsQuery, 0, resp, 0, safeEnd)
    // Flags: Response (0x80), Recursion Desired (0x01), Recursion Available (0x80) -> 0x8180, RCODE = 0 (NOERROR)
    resp[2] = 0x81.toByte()
    resp[3] = 0x80.toByte()
    // ANCOUNT = 0 (No answers)
    resp[6] = 0x00.toByte()
    resp[7] = 0x00.toByte()
    // NSCOUNT = 0
    resp[8] = 0x00.toByte()
    resp[9] = 0x00.toByte()
    // ARCOUNT = 0
    resp[10] = 0x00.toByte()
    resp[11] = 0x00.toByte()
    return resp
  }

  private fun buildIpv4UdpReply(
    reqPacket: ByteArray,
    reqIhl: Int,
    dnsPayload: ByteArray,
  ): ByteArray {
    val ipHeaderLen = 20
    val udpHeaderLen = 8
    val totalLen = ipHeaderLen + udpHeaderLen + dnsPayload.size
    val out = ByteArray(totalLen)

    // IPv4 Header
    out[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
    out[1] = 0x00.toByte()
    out[2] = ((totalLen ushr 8) and 0xFF).toByte()
    out[3] = (totalLen and 0xFF).toByte()
    out[4] = 0x00.toByte()
    out[5] = 0x00.toByte()
    out[6] = 0x40.toByte() // Don't Fragment
    out[7] = 0x00.toByte()
    out[8] = 64.toByte() // TTL
    out[9] = 17.toByte() // Protocol = UDP (17)

    // Swap source IP (req 12..15) and destination IP (req 16..19)
    System.arraycopy(reqPacket, 16, out, 12, 4) // Src IP = original Dst IP
    System.arraycopy(reqPacket, 12, out, 16, 4) // Dst IP = original Src IP

    // Compute IPv4 header checksum
    var sum = 0
    for (i in 0 until ipHeaderLen step 2) {
      val word = ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
      sum += word
    }
    while ((sum ushr 16) != 0) {
      sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    val checksum = sum.inv() and 0xFFFF
    out[10] = ((checksum ushr 8) and 0xFF).toByte()
    out[11] = (checksum and 0xFF).toByte()

    // UDP Header: swap source port and destination port
    out[20] = reqPacket[reqIhl + 2]
    out[21] = reqPacket[reqIhl + 3]
    out[22] = reqPacket[reqIhl]
    out[23] = reqPacket[reqIhl + 1]

    val udpLen = udpHeaderLen + dnsPayload.size
    out[24] = ((udpLen ushr 8) and 0xFF).toByte()
    out[25] = (udpLen and 0xFF).toByte()
    // UDP checksum is optional in IPv4 (0x0000)
    out[26] = 0x00.toByte()
    out[27] = 0x00.toByte()

    // DNS Payload
    System.arraycopy(dnsPayload, 0, out, 28, dnsPayload.size)
    return out
  }
}
