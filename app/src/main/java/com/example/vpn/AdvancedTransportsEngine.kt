package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Advanced V2Ray / Xray Transport & Security Engine supporting:
 * 1. TCP HTTP Header Obfuscation (`type=tcp&headerType=http`)
 * 2. gRPC (`type=grpc`, `serviceName=...`) & HTTP/2 (`type=h2` / `type=http`) Framing over HTTP/2 Streams
 * 3. XHTTP / SplitHTTP (`type=xhttp` / `type=splithttp`) Chunked Streaming Transport
 * 4. mKCP (`type=kcp` / `type=mkcp`) Reliable UDP ARQ Transport
 * 5. VLESS Flow (`flow=xtls-rprx-vision`) Padding/Unpadding Framer
 * 6. VLESS Reality (`security=reality`, `pbk`, `sid`) X25519 + HKDF-SHA256 + AES-GCM ClientHello Auth
 */
object AdvancedTransportsEngine {

  private val rng = SecureRandom()
  private val H2_CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

  // ============================================================================
  // 1. TCP HTTP Header Obfuscation (type=tcp & headerType=http)
  // ============================================================================

  fun wrapTcpHttpObfuscation(
    config: V2RayConfig,
    rawIn: InputStream,
    rawOut: OutputStream,
  ): Pair<InputStream, OutputStream> {
    val host =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .split(",")
        .first()
        .trim()
    val path =
      config.path
        .ifBlank { "/" }
        .split(",")
        .first()
        .trim()
        .let { if (it.startsWith("/")) it else "/$it" }

    val obfsOut =
      object : FilterOutputStream(rawOut) {
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
            val httpHeader =
              "GET $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: ${GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT}\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                "Accept-Language: en-US,en;q=0.8\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Pragma: no-cache\r\n" +
                "Cache-Control: no-cache\r\n" +
                "Connection: keep-alive\r\n\r\n"
            val hdrBytes = httpHeader.toByteArray(Charsets.US_ASCII)
            val combined = ByteArray(hdrBytes.size + len)
            System.arraycopy(hdrBytes, 0, combined, 0, hdrBytes.size)
            System.arraycopy(b, off, combined, hdrBytes.size, len)
            out.write(combined)
            out.flush()
          } else {
            out.write(b, off, len)
          }
        }
      }

    val obfsIn =
      object : FilterInputStream(rawIn) {
        private var headerStripped = false
        private var leftover: ByteArray = ByteArray(0)
        private var leftoverPos = 0

        @Synchronized
        private fun ensureStripped() {
          if (headerStripped) return
          headerStripped = true
          val peek = ByteArray(5)
          var readCount = 0
          while (readCount < 5) {
            val n = `in`.read(peek, readCount, 5 - readCount)
            if (n <= 0) break
            readCount += n
          }
          if (readCount <= 0) return
          val prefix = String(peek, 0, readCount, Charsets.ISO_8859_1)
          if (!prefix.startsWith("HTTP/")) {
            leftover = peek.copyOf(readCount)
            leftoverPos = 0
            return
          }
          // Consume until \r\n\r\n
          var state = 0
          var scanned = 0
          while (scanned < 8192) {
            val b = `in`.read()
            if (b == -1) break
            scanned++
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
          ensureStripped()
          if (leftoverPos < leftover.size) {
            val take = minOf(len, leftover.size - leftoverPos)
            System.arraycopy(leftover, leftoverPos, b, off, take)
            leftoverPos += take
            return take
          }
          return `in`.read(b, off, len)
        }
      }

    return Pair(obfsIn, obfsOut)
  }

  // ============================================================================
  // 2. gRPC (`type=grpc`) & HTTP/2 (`type=h2`) Transport over HTTP/2 Framing
  // ============================================================================

  fun openGrpcOrH2Stream(
    config: V2RayConfig,
    rawIn: InputStream,
    rawOut: OutputStream,
    isGrpc: Boolean,
  ): Pair<InputStream, OutputStream> {
    val authority =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')
    val service = config.serviceName.ifBlank { config.path.removePrefix("/") }.trim()
    val h2Path =
      if (isGrpc) {
        if (service.isEmpty()) "/GunService/Tun"
        else if (service.contains("/")) "/${service.trimStart('/')}"
        else "/$service/Tun"
      } else {
        config.path.ifBlank { "/" }.let { if (it.startsWith("/")) it else "/$it" }
      }

    // 1. Send HTTP/2 Client Preface + Initial SETTINGS + WINDOW_UPDATE
    val initBuf = ByteArrayOutputStream(256)
    initBuf.write(H2_CLIENT_PREFACE)
    // SETTINGS frame (type=0x04, flags=0x00, streamId=0): INITIAL_WINDOW_SIZE(4)=4MB
    val settingsPayload =
      ByteBuffer.allocate(6)
        .order(ByteOrder.BIG_ENDIAN)
        .putShort(0x0004)
        .putInt(4 * 1024 * 1024)
        .array()
    writeH2Frame(initBuf, type = 0x04, flags = 0x00, streamId = 0, payload = settingsPayload)
    // WINDOW_UPDATE frame (type=0x08, flags=0x00, streamId=0): increment = 4MB
    val winPayload =
      ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(4 * 1024 * 1024).array()
    writeH2Frame(initBuf, type = 0x08, flags = 0x00, streamId = 0, payload = winPayload)

    // HEADERS frame on Stream 1 (type=0x01, flags=0x04 END_HEADERS, streamId=1)
    val hpackBlock = buildHpackRequestBlock(authority, h2Path, isGrpc)
    writeH2Frame(initBuf, type = 0x01, flags = 0x04, streamId = 1, payload = hpackBlock)
    rawOut.write(initBuf.toByteArray())
    rawOut.flush()

    val h2Out =
      object : FilterOutputStream(rawOut) {
        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          val framedPayload =
            if (isGrpc) {
              encodeGrpcTunHunk(b, off, len)
            } else {
              b.copyOfRange(off, off + len)
            }
          var pos = 0
          val frameBuf = ByteArrayOutputStream(framedPayload.size + 32)
          while (pos < framedPayload.size) {
            val take = minOf(16384, framedPayload.size - pos)
            writeH2Frame(
              frameBuf,
              type = 0x00, // DATA
              flags = 0x00,
              streamId = 1,
              payload = framedPayload.copyOfRange(pos, pos + take),
            )
            pos += take
          }
          out.write(frameBuf.toByteArray())
          out.flush()
        }

        @Synchronized
        fun sendFrameSafe(type: Int, flags: Int, streamId: Int, payload: ByteArray) {
          try {
            val buf = ByteArrayOutputStream(9 + payload.size)
            writeH2Frame(buf, type, flags, streamId, payload)
            out.write(buf.toByteArray())
            out.flush()
          } catch (_: Exception) {}
        }
      }

    val h2In =
      object : FilterInputStream(rawIn) {
        private val dataIn = DataInputStream(rawIn)
        private val grpcAccum = ByteArrayOutputStream()
        private var currentChunk: ByteArray = ByteArray(0)
        private var currentPos = 0

        private fun readNextDataPayload(): Boolean {
          while (true) {
            if (isGrpc) {
              val extracted = tryExtractGrpcHunk(grpcAccum)
              if (extracted != null && extracted.isNotEmpty()) {
                currentChunk = extracted
                currentPos = 0
                return true
              }
            }
            val hdr = ByteArray(9)
            val first = `in`.read()
            if (first == -1) return false
            hdr[0] = first.toByte()
            dataIn.readFully(hdr, 1, 8)
            val length =
              ((hdr[0].toInt() and 0xFF) shl 16) or
                ((hdr[1].toInt() and 0xFF) shl 8) or
                (hdr[2].toInt() and 0xFF)
            val type = hdr[3].toInt() and 0xFF
            val flags = hdr[4].toInt() and 0xFF
            val streamId =
              ((hdr[5].toInt() and 0x7F) shl 24) or
                ((hdr[6].toInt() and 0xFF) shl 16) or
                ((hdr[7].toInt() and 0xFF) shl 8) or
                (hdr[8].toInt() and 0xFF)

            val payload = ByteArray(length)
            if (length > 0) {
              dataIn.readFully(payload)
            }

            when (type) {
              0x00 -> { // DATA
                var dataStart = 0
                var dataEnd = payload.size
                if ((flags and 0x08) != 0 && payload.isNotEmpty()) { // PADDED
                  val padLen = payload[0].toInt() and 0xFF
                  dataStart = 1
                  dataEnd = (payload.size - padLen).coerceAtLeast(1)
                }
                val actualLen = dataEnd - dataStart
                if (actualLen > 0 && streamId == 1) {
                  // Send WINDOW_UPDATE for connection & stream
                  val win = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(actualLen).array()
                  h2Out.sendFrameSafe(0x08, 0x00, 0, win)
                  h2Out.sendFrameSafe(0x08, 0x00, 1, win)
                  val dataSlice = payload.copyOfRange(dataStart, dataEnd)
                  if (isGrpc) {
                    grpcAccum.write(dataSlice)
                  } else {
                    currentChunk = dataSlice
                    currentPos = 0
                    return true
                  }
                }
                if ((flags and 0x01) != 0 && streamId == 1) { // END_STREAM
                  return false
                }
              }
              0x04 -> { // SETTINGS
                if ((flags and 0x01) == 0) {
                  // Send SETTINGS ACK
                  h2Out.sendFrameSafe(0x04, 0x01, 0, ByteArray(0))
                }
              }
              0x06 -> { // PING
                if ((flags and 0x01) == 0 && payload.size == 8) {
                  h2Out.sendFrameSafe(0x06, 0x01, 0, payload)
                }
              }
              0x03, 0x07 -> { // RST_STREAM or GOAWAY
                return false
              }
            }
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
          while (currentPos >= currentChunk.size) {
            if (!readNextDataPayload()) return -1
          }
          val take = minOf(len, currentChunk.size - currentPos)
          System.arraycopy(currentChunk, currentPos, b, off, take)
          currentPos += take
          return take
        }
      }

    return Pair(h2In, h2Out)
  }

  private fun writeH2Frame(
    out: ByteArrayOutputStream,
    type: Int,
    flags: Int,
    streamId: Int,
    payload: ByteArray,
  ) {
    val len = payload.size
    out.write((len ushr 16) and 0xFF)
    out.write((len ushr 8) and 0xFF)
    out.write(len and 0xFF)
    out.write(type and 0xFF)
    out.write(flags and 0xFF)
    out.write((streamId ushr 24) and 0x7F)
    out.write((streamId ushr 16) and 0xFF)
    out.write((streamId ushr 8) and 0xFF)
    out.write(streamId and 0xFF)
    out.write(payload)
  }

  private fun buildHpackRequestBlock(authority: String, path: String, isGrpc: Boolean): ByteArray {
    val out = ByteArrayOutputStream(128)
    // :method = POST (static table index 3 -> 0x83)
    out.write(0x83)
    // :scheme = https (static table index 7 -> 0x87)
    out.write(0x87)
    // :path (literal header field without indexing, name index 4 -> 0x04)
    out.write(0x04)
    writeHpackString(out, path)
    // :authority (literal header field without indexing, name index 1 -> 0x01)
    out.write(0x01)
    writeHpackString(out, authority)
    if (isGrpc) {
      // content-type (name index 31 -> 0x0F, 0x10): application/grpc
      writeHpackLiteralHeader(out, "content-type", "application/grpc")
      writeHpackLiteralHeader(out, "te", "trailers")
      writeHpackLiteralHeader(out, "user-agent", "grpc-go/1.64.0")
    } else {
      writeHpackLiteralHeader(out, "user-agent", GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT)
    }
    return out.toByteArray()
  }

  private fun writeHpackLiteralHeader(out: ByteArrayOutputStream, name: String, value: String) {
    out.write(0x00)
    writeHpackString(out, name.lowercase())
    writeHpackString(out, value)
  }

  private fun writeHpackString(out: ByteArrayOutputStream, str: String) {
    val bytes = str.toByteArray(Charsets.US_ASCII)
    writeHpackInt(out, bytes.size, 7, 0x00)
    out.write(bytes)
  }

  private fun writeHpackInt(out: ByteArrayOutputStream, value: Int, prefixBits: Int, mask: Int) {
    val maxPrefix = (1 shl prefixBits) - 1
    if (value < maxPrefix) {
      out.write(mask or value)
    } else {
      out.write(mask or maxPrefix)
      var rem = value - maxPrefix
      while (rem >= 128) {
        out.write((rem and 0x7F) or 0x80)
        rem = rem ushr 7
      }
      out.write(rem)
    }
  }

  private fun encodeGrpcTunHunk(b: ByteArray, off: Int, len: Int): ByteArray {
    // Protobuf Hunk: tag 0x0A (field 1, wire type 2) + varint(len) + bytes
    val proto = ByteArrayOutputStream(len + 16)
    proto.write(0x0A)
    var v = len
    while (v >= 0x80) {
      proto.write((v and 0x7F) or 0x80)
      v = v ushr 7
    }
    proto.write(v)
    proto.write(b, off, len)
    val protoBytes = proto.toByteArray()

    // gRPC 5-byte prefix: [0x00][4-byte big-endian length]
    val grpc = ByteArray(5 + protoBytes.size)
    grpc[0] = 0x00
    grpc[1] = ((protoBytes.size ushr 24) and 0xFF).toByte()
    grpc[2] = ((protoBytes.size ushr 16) and 0xFF).toByte()
    grpc[3] = ((protoBytes.size ushr 8) and 0xFF).toByte()
    grpc[4] = (protoBytes.size and 0xFF).toByte()
    System.arraycopy(protoBytes, 0, grpc, 5, protoBytes.size)
    return grpc
  }

  private fun tryExtractGrpcHunk(accum: ByteArrayOutputStream): ByteArray? {
    val arr = accum.toByteArray()
    if (arr.size < 5) return null
    val msgLen =
      ((arr[1].toInt() and 0xFF) shl 24) or
        ((arr[2].toInt() and 0xFF) shl 16) or
        ((arr[3].toInt() and 0xFF) shl 8) or
        (arr[4].toInt() and 0xFF)
    if (arr.size < 5 + msgLen) return null

    // Consume this gRPC message from accum
    accum.reset()
    if (arr.size > 5 + msgLen) {
      accum.write(arr, 5 + msgLen, arr.size - (5 + msgLen))
    }

    if (msgLen <= 0) return ByteArray(0)
    // Parse protobuf tag 0x0A + varint length
    var pos = 5
    val end = 5 + msgLen
    if (arr[pos].toInt() == 0x0A) {
      pos++
      var hunkLen = 0
      var shift = 0
      while (pos < end) {
        val b = arr[pos++].toInt() and 0xFF
        hunkLen = hunkLen or ((b and 0x7F) shl shift)
        if ((b and 0x80) == 0) break
        shift += 7
      }
      val safeEnd = minOf(end, pos + hunkLen)
      return arr.copyOfRange(pos, safeEnd)
    }
    return arr.copyOfRange(5, end)
  }

  // ============================================================================
  // 3. XHTTP / SplitHTTP (`type=xhttp` or `type=splithttp`) Streaming Transport
  // ============================================================================

  fun openXhttpStream(
    config: V2RayConfig,
    rawIn: InputStream,
    rawOut: OutputStream,
  ): Pair<InputStream, OutputStream> {
    val host =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')
    val basePath =
      config.path
        .ifBlank { "/" }
        .let { if (it.startsWith("/")) it else "/$it" }
        .trimEnd('/')
    val sessionId = UUID.randomUUID().toString()
    val fullPath = if (basePath.isEmpty()) "/$sessionId" else "$basePath/$sessionId"

    val xhttpOut =
      object : FilterOutputStream(rawOut) {
        private var reqSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          val outBuf = ByteArrayOutputStream(len + 256)
          if (!reqSent) {
            reqSent = true
            val req =
              "POST $fullPath HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: ${GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT}\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "X-Accel-Buffering: no\r\n" +
                "Connection: keep-alive\r\n\r\n"
            outBuf.write(req.toByteArray(Charsets.US_ASCII))
          }
          val chunkHdr = "${Integer.toHexString(len)}\r\n".toByteArray(Charsets.US_ASCII)
          outBuf.write(chunkHdr)
          outBuf.write(b, off, len)
          outBuf.write(byteArrayOf('\r'.code.toByte(), '\n'.code.toByte()))
          out.write(outBuf.toByteArray())
          out.flush()
        }
      }

    val xhttpIn =
      object : FilterInputStream(rawIn) {
        private var headerRead = false
        private var isChunked = false
        private var chunkRemaining = 0

        @Synchronized
        private fun ensureHttpHeader() {
          if (headerRead) return
          headerRead = true
          val hdrBuf = ByteArrayOutputStream(512)
          var state = 0
          while (hdrBuf.size() < 8192) {
            val b = `in`.read()
            if (b == -1) throw EOFException("EOF reading XHTTP response header")
            hdrBuf.write(b)
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
          val headers = hdrBuf.toString("US-ASCII")
          isChunked = headers.contains("Transfer-Encoding: chunked", ignoreCase = true)
        }

        private fun readChunkLine(): String {
          val sb = StringBuilder(16)
          while (sb.length < 64) {
            val b = `in`.read()
            if (b == -1) break
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
          }
          return sb.toString().trim()
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
          ensureHttpHeader()
          if (!isChunked) {
            return `in`.read(b, off, len)
          }
          while (chunkRemaining <= 0) {
            val line = readChunkLine().substringBefore(";")
            if (line.isEmpty()) continue
            val size = line.toIntOrNull(16) ?: return -1
            if (size == 0) return -1
            chunkRemaining = size
          }
          val toRead = minOf(len, chunkRemaining)
          val n = `in`.read(b, off, toRead)
          if (n <= 0) return -1
          chunkRemaining -= n
          if (chunkRemaining == 0) {
            // Consume trailing CRLF
            `in`.read()
            `in`.read()
          }
          return n
        }
      }

    return Pair(xhttpIn, xhttpOut)
  }

  // ============================================================================
  // 4. mKCP (`type=kcp` / `type=mkcp`) Reliable UDP Transport
  // ============================================================================

  fun openMkcpTransport(
    config: V2RayConfig,
    timeoutMs: Int,
    protector: ((Socket) -> Boolean)?,
  ): Pair<InputStream, OutputStream> {
    val udpSocket = DatagramSocket()
    udpSocket.soTimeout = timeoutMs
    val hostIp =
      config.resolvedIp.ifBlank {
        V2RayOutboundClient.resolveEndpointIpv4(config.address) ?: config.address
      }
    val remoteAddr = InetSocketAddress(InetAddress.getByName(hostIp), config.port)
    val conv = rng.nextInt()
    var sendSn = 0
    var recvNextSn = 0

    val kcpOut =
      object : OutputStream() {
        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          var pos = off
          var rem = len
          while (rem > 0) {
            val take = minOf(1200, rem)
            val seg = ByteBuffer.allocate(24 + take).order(ByteOrder.LITTLE_ENDIAN)
            seg.putInt(conv)
            seg.put(81.toByte()) // IKCP_CMD_PUSH = 81
            seg.put(0.toByte()) // frg = 0
            seg.putShort(256.toShort()) // wnd
            seg.putInt((System.currentTimeMillis() and 0xFFFFFFFFL).toInt())
            seg.putInt(sendSn++)
            seg.putInt(recvNextSn)
            seg.putInt(take)
            seg.put(b, pos, take)
            val rawSeg = seg.array()
            val pkt = buildMkcpWirePacket(rawSeg)
            udpSocket.send(DatagramPacket(pkt, pkt.size, remoteAddr))
            pos += take
            rem -= take
          }
        }

        override fun close() {
          try {
            udpSocket.close()
          } catch (_: Exception) {}
        }
      }

    val kcpIn =
      object : InputStream() {
        private var currentData: ByteArray = ByteArray(0)
        private var currentPos = 0

        private fun receiveNextSegment(): Boolean {
          val buf = ByteArray(2048)
          val pkt = DatagramPacket(buf, buf.size)
          while (true) {
            udpSocket.receive(pkt)
            if (pkt.length < 28) continue
            // Skip 4-byte FNV-1a auth + 2-byte length if present, or parse KCP header
            val offset = if (pkt.length >= 30) 6 else 0
            if (pkt.length < offset + 24) continue
            val bb = ByteBuffer.wrap(buf, offset, pkt.length - offset).order(ByteOrder.LITTLE_ENDIAN)
            bb.int // conv
            val cmd = bb.get().toInt() and 0xFF
            bb.get() // frg
            bb.short // wnd
            val ts = bb.int
            val sn = bb.int
            bb.int // una
            val segLen = bb.int
            if (cmd == 81 && segLen in 1..(pkt.length - offset - 24)) {
              recvNextSn = maxOf(recvNextSn, sn + 1)
              val payload = ByteArray(segLen)
              bb.get(payload)
              // Send KCP ACK (cmd = 82)
              try {
                val ack = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                ack.putInt(conv)
                ack.put(82.toByte())
                ack.put(0.toByte())
                ack.putShort(256.toShort())
                ack.putInt(ts)
                ack.putInt(sn)
                ack.putInt(recvNextSn)
                ack.putInt(0)
                val ackWire = buildMkcpWirePacket(ack.array())
                udpSocket.send(DatagramPacket(ackWire, ackWire.size, remoteAddr))
              } catch (_: Exception) {}
              currentData = payload
              currentPos = 0
              return true
            }
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
            if (!receiveNextSegment()) return -1
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

    return Pair(kcpIn, kcpOut)
  }

  private fun buildMkcpWirePacket(kcpSegment: ByteArray): ByteArray {
    // Xray mKCP plain packet format: [4-byte FNV1a32][2-byte big-endian length][kcpSegment]
    val body = ByteArray(2 + kcpSegment.size)
    body[0] = ((kcpSegment.size ushr 8) and 0xFF).toByte()
    body[1] = (kcpSegment.size and 0xFF).toByte()
    System.arraycopy(kcpSegment, 0, body, 2, kcpSegment.size)
    var hash = 0x811c9dc5.toInt()
    for (b in body) {
      hash = hash xor (b.toInt() and 0xFF)
      hash *= 0x01000193
    }
    val out = ByteBuffer.allocate(4 + body.size).order(ByteOrder.BIG_ENDIAN)
    out.putInt(hash)
    out.put(body)
    return out.array()
  }

  // ============================================================================
  // 5. VLESS Flow (`xtls-rprx-vision`) & VLESS Reality (`security=reality`)
  // ============================================================================

  /**
   * Encodes VLESS `Addons` protobuf message (`message Addons { string Flow = 1; }`).
   */
  fun encodeVlessFlowAddon(flow: String): ByteArray {
    val cleanFlow = flow.trim()
    if (cleanFlow.isEmpty()) return ByteArray(0)
    val flowBytes = cleanFlow.toByteArray(Charsets.US_ASCII)
    val out = ByteArray(2 + flowBytes.size)
    out[0] = 0x0A // field 1, wire type 2 (length-delimited)
    out[1] = (flowBytes.size and 0xFF).toByte()
    System.arraycopy(flowBytes, 0, out, 2, flowBytes.size)
    return out
  }

  /**
   * Wraps VLESS stream with XTLS Vision padding/unpadding framer (`flow=xtls-rprx-vision`).
   */
  fun wrapXtlsVisionStream(
    uuidBytes: ByteArray,
    vlessIn: InputStream,
    vlessOut: OutputStream,
  ): Pair<InputStream, OutputStream> {
    val visionOut =
      object : FilterOutputStream(vlessOut) {
        private var firstVisionFrame = true
        private var directSpliceMode = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          if (directSpliceMode) {
            out.write(b, off, len)
            out.flush()
            return
          }
          // Inspect if inner TLS handshake has reached Application Data (0x17 0x03 0x03)
          val isAppData =
            len >= 5 &&
              (b[off].toInt() and 0xFF) == 0x17 &&
              (b[off + 1].toInt() and 0xFF) == 0x03
          val command: Byte = if (isAppData) 0x02 else 0x00 // 0x02 = direct splice, 0x00 = continue padding
          val padLen = if (firstVisionFrame) rng.nextInt(64) + 32 else rng.nextInt(32)
          val frame = ByteArrayOutputStream(len + padLen + 32)
          if (firstVisionFrame) {
            firstVisionFrame = false
            frame.write(uuidBytes)
          }
          frame.write(command.toInt())
          frame.write((len ushr 8) and 0xFF)
          frame.write(len and 0xFF)
          frame.write((padLen ushr 8) and 0xFF)
          frame.write(padLen and 0xFF)
          frame.write(b, off, len)
          if (padLen > 0) {
            val pad = ByteArray(padLen).also { rng.nextBytes(it) }
            frame.write(pad)
          }
          if (isAppData) {
            directSpliceMode = true
          }
          out.write(frame.toByteArray())
          out.flush()
        }
      }

    val visionIn =
      object : FilterInputStream(vlessIn) {
        private val dataIn = DataInputStream(vlessIn)
        private var firstServerFrame = true
        private var directReadMode = false
        private var currentPayload: ByteArray = ByteArray(0)
        private var currentPos = 0

        private fun readNextVisionBlock(): Boolean {
          if (directReadMode) return false
          if (firstServerFrame) {
            firstServerFrame = false
            // Peek first byte: if server starts with TLS record 0x16 (ServerHello) directly or UUID
            val firstByte = `in`.read()
            if (firstByte == -1) return false
            if (firstByte == (uuidBytes[0].toInt() and 0xFF)) {
              val restUuid = ByteArray(15)
              dataIn.readFully(restUuid)
            } else {
              // Server sent unpadded or direct TLS bytes
              directReadMode = true
              currentPayload = byteArrayOf(firstByte.toByte())
              currentPos = 0
              return true
            }
          }
          val cmd = `in`.read()
          if (cmd == -1) return false
          val cLenHigh = `in`.read()
          val cLenLow = `in`.read()
          val pLenHigh = `in`.read()
          val pLenLow = `in`.read()
          if (cLenHigh < 0 || cLenLow < 0 || pLenHigh < 0 || pLenLow < 0) return false
          val contentLen = ((cLenHigh and 0xFF) shl 8) or (cLenLow and 0xFF)
          val paddingLen = ((pLenHigh and 0xFF) shl 8) or (pLenLow and 0xFF)
          val buf = ByteArray(contentLen)
          if (contentLen > 0) dataIn.readFully(buf)
          if (paddingLen > 0) dataIn.readFully(ByteArray(paddingLen))
          if (cmd == 0x01 || cmd == 0x02) {
            directReadMode = true
          }
          currentPayload = buf
          currentPos = 0
          return true
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
          if (currentPos < currentPayload.size) {
            val take = minOf(len, currentPayload.size - currentPos)
            System.arraycopy(currentPayload, currentPos, b, off, take)
            currentPos += take
            return take
          }
          if (directReadMode) {
            return `in`.read(b, off, len)
          }
          while (currentPos >= currentPayload.size) {
            if (!readNextVisionBlock()) {
              return if (directReadMode) `in`.read(b, off, len) else -1
            }
          }
          val take = minOf(len, currentPayload.size - currentPos)
          System.arraycopy(currentPayload, currentPos, b, off, take)
          currentPos += take
          return take
        }
      }

    return Pair(visionIn, visionOut)
  }

  /**
   * Establishes a VLESS Reality (`security=reality`) TLS 1.3 connection by injecting the
   * X25519 + HKDF-SHA256 + AES-256-GCM authenticated SessionId into the outgoing TLS ClientHello.
   */
  fun establishRealityTlsStreams(
    rawSocket: Socket,
    config: V2RayConfig,
    timeoutMs: Int,
  ): Triple<InputStream, OutputStream, javax.net.ssl.SSLSocket?> {
    val sniHost =
      config.sni
        .ifBlank { config.hostHeader }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')
    val serverPubKey =
      V2RayConfigParser.decodeBase64BytesSafe(config.pbk)?.takeIf { it.size == 32 }
        ?: throw IOException("Invalid Reality pbk: ${config.pbk}")
    val shortIdBytes = parseHexShortId(config.shortId)

    val realityRewriterOut =
      object : FilterOutputStream(rawSocket.getOutputStream()) {
        private var clientHelloPatched = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (!clientHelloPatched && len >= 48 && (b[off].toInt() and 0xFF) == 0x16) {
            clientHelloPatched = true
            val patched = patchRealityClientHello(b.copyOfRange(off, off + len), serverPubKey, shortIdBytes)
            out.write(patched)
            out.flush()
          } else {
            out.write(b, off, len)
          }
        }
      }

    val (tlsIn, tlsOut) =
      GfwKnockerXrayCore.openSslEngineOverStreams(
        sslContext = V2RayOutboundClient.permissiveSslContext,
        rawIn = BufferedInputStream(rawSocket.getInputStream(), 16384),
        rawOut = realityRewriterOut,
        sniHost = sniHost,
        port = config.port,
      )
    return Triple(BufferedInputStream(tlsIn, 16384), tlsOut, null)
  }

  private fun patchRealityClientHello(
    record: ByteArray,
    serverPubKey: ByteArray,
    shortId8: ByteArray,
  ): ByteArray {
    // TLS record header is 5 bytes [0x16, 0x03, 0x01, lenHi, lenLo], Handshake header is 4 bytes [0x01, len3],
    // Version is 2 bytes [0x03, 0x03], Random is 32 bytes at offset 11..43, SessionId length is at offset 43.
    if (record.size < 80 || (record[5].toInt() and 0xFF) != 0x01) return record
    val sidLen = record[43].toInt() and 0xFF
    if (sidLen != 32 || record.size < 44 + 32) return record

    val clientRandom = record.copyOfRange(11, 43)
    // Locate X25519 key_share (group 0x001d, 32 bytes) in ClientHello extensions or generate ephemeral X25519
    val ephPriv = ByteArray(32).also { rng.nextBytes(it) }
    val ephPub = X25519Pure.scalarMultBase(ephPriv)
    replaceX25519KeyShareInClientHello(record, ephPub)

    val sharedSecret = X25519Pure.scalarMult(ephPriv, serverPubKey)
    val salt20 = clientRandom.copyOfRange(0, 20)
    val nonce12 = clientRandom.copyOfRange(20, 32)
    val authKey = hkdfSha256(sharedSecret, salt20, "REALITY".toByteArray(Charsets.US_ASCII), 16)

    // Plaintext SessionId (16 bytes): [ver_x=1, ver_y=8, ver_z=4, reserved=0, timestamp(4B BE), shortId(8B)]
    val plainSid = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
    plainSid.put(1.toByte()).put(8.toByte()).put(4.toByte()).put(0.toByte())
    plainSid.putInt((System.currentTimeMillis() / 1000L).toInt())
    plainSid.put(shortId8, 0, 8)

    // AAD is the Handshake message (record[5..end]) with SessionId zeroed out
    val aad = record.copyOfRange(5, record.size)
    for (i in 0 until 32) {
      aad[39 + i] = 0
    }
    val encryptedSid32 =
      VmessAndShadowsocksEngine.aesGcmEncrypt(authKey, nonce12, plainSid.array(), aad)
    if (encryptedSid32.size == 32) {
      System.arraycopy(encryptedSid32, 0, record, 44, 32)
    }
    return record
  }

  private fun replaceX25519KeyShareInClientHello(record: ByteArray, newPub32: ByteArray) {
    // Search for key_share entry [0x00, 0x1d, 0x00, 0x20] inside extensions
    var i = 76
    while (i + 36 <= record.size) {
      if ((record[i].toInt() and 0xFF) == 0x00 &&
        (record[i + 1].toInt() and 0xFF) == 0x1D &&
        (record[i + 2].toInt() and 0xFF) == 0x00 &&
        (record[i + 3].toInt() and 0xFF) == 0x20
      ) {
        System.arraycopy(newPub32, 0, record, i + 4, 32)
        return
      }
      i++
    }
  }

  private fun parseHexShortId(sid: String): ByteArray {
    val clean = sid.trim().lowercase()
    val out = ByteArray(8)
    var i = 0
    while (i + 1 < clean.length && (i / 2) < 8) {
      val byteVal = clean.substring(i, i + 2).toIntOrNull(16) ?: break
      out[i / 2] = byteVal.toByte()
      i += 2
    }
    return out
  }

  internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
    val prk = mac.doFinal(ikm)
    mac.init(SecretKeySpec(prk, "HmacSHA256"))
    val okm = ByteArrayOutputStream(outLen + 32)
    var t = ByteArray(0)
    var counter = 1
    while (okm.size() < outLen) {
      mac.reset()
      mac.update(t)
      mac.update(info)
      mac.update(counter.toByte())
      t = mac.doFinal()
      okm.write(t)
      counter++
    }
    return okm.toByteArray().copyOf(outLen)
  }
}

/**
 * Pure-Kotlin RFC 7748 Curve25519 (X25519) key agreement for VLESS Reality and WireGuard
 * on all Android API levels (API 21+).
 */
internal object X25519Pure {
  private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
  private val A24: BigInteger = BigInteger.valueOf(121665)
  private val BASE_POINT = ByteArray(32).apply { this[0] = 9 }

  fun scalarMultBase(scalar32: ByteArray): ByteArray = scalarMult(scalar32, BASE_POINT)

  fun scalarMult(scalar32: ByteArray, uBytes32: ByteArray): ByteArray {
    val kBytes = scalar32.copyOf(32)
    kBytes[0] = (kBytes[0].toInt() and 248).toByte()
    kBytes[31] = (kBytes[31].toInt() and 127).toByte()
    kBytes[31] = (kBytes[31].toInt() or 64).toByte()

    val uClean = uBytes32.copyOf(32)
    uClean[31] = (uClean[31].toInt() and 127).toByte()

    val k = BigInteger(1, kBytes.reversedArray())
    val u = BigInteger(1, uClean.reversedArray()).mod(P)

    var x1 = u
    var x2 = BigInteger.ONE
    var z2 = BigInteger.ZERO
    var x3 = u
    var z3 = BigInteger.ONE
    var swap = 0

    for (t in 254 downTo 0) {
      val kt = if (k.testBit(t)) 1 else 0
      swap = swap xor kt
      if (swap == 1) {
        val tx = x2; x2 = x3; x3 = tx
        val tz = z2; z2 = z3; z3 = tz
      }
      swap = kt

      val a = x2.add(z2).mod(P)
      val aa = a.multiply(a).mod(P)
      val b = x2.subtract(z2).mod(P)
      val bb = b.multiply(b).mod(P)
      val e = aa.subtract(bb).mod(P)
      val c = x3.add(z3).mod(P)
      val d = x3.subtract(z3).mod(P)
      val da = d.multiply(a).mod(P)
      val cb = c.multiply(b).mod(P)
      val sum = da.add(cb).mod(P)
      x3 = sum.multiply(sum).mod(P)
      val diff = da.subtract(cb).mod(P)
      z3 = x1.multiply(diff.multiply(diff).mod(P)).mod(P)
      x2 = aa.multiply(bb).mod(P)
      z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
    }
    if (swap == 1) {
      x2 = x3
      z2 = z3
    }
    val res = x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P)
    val be = res.toByteArray()
    val out = ByteArray(32)
    for (i in 0 until 32) {
      val idx = be.size - 1 - i
      out[i] = if (idx >= 0) be[idx] else 0
    }
    return out
  }
}
