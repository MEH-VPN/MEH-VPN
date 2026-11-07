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
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLSocket

/**
 * Outbound Protocol Engine for:
 * 1. VMess AEAD (V2Ray / Xray-core standard AEAD header + AES-128-GCM / ChaCha20-Poly1305 / None chunk stream)
 * 2. Shadowsocks AEAD (`aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`) & Shadowsocks 2022 (`2022-blake3-*`) + UDP
 * 3. Direct SOCKS5 (`socks://`, `socks5://`) with optional RFC 1929 Username/Password authentication
 * 4. Direct HTTP/HTTPS CONNECT Proxy (`http://`, `https://`) with optional Basic authentication
 */
object VmessAndShadowsocksEngine {

  private val rng = SecureRandom()
  private val VMESS_CMD_KEY_SALT =
    "c48619fe-8f02-49e0-b9e9-edf763e17e21".toByteArray(Charsets.US_ASCII)
  private val SS_SUBKEY_INFO = "ss-subkey".toByteArray(Charsets.US_ASCII)

  // ============================================================================
  // 1. VMess AEAD Outbound Protocol
  // ============================================================================

  fun isSupportedShadowsocksCipher(cipher: String): Boolean {
    return when (cipher.lowercase().trim()) {
      "aes-128-gcm",
      "aes-256-gcm",
      "chacha20-ietf-poly1305",
      "chacha20-poly1305",
      "xchacha20-ietf-poly1305",
      "2022-blake3-aes-128-gcm",
      "2022-blake3-aes-256-gcm",
      "2022-blake3-chacha20-poly1305",
      "none",
      "plain" -> true
      else -> false
    }
  }

  fun setupVmessStream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    isUdp: Boolean = false,
  ): V2RayOutboundClient.TunnelConnection {
    val uuidBytes =
      V2RayOutboundClient.parseUuidBytesInternal(config.authId)
        ?: throw IOException("Invalid VMess UUID: ${config.authId}")

    val cmdKey = computeVmessCmdKey(uuidBytes)
    val reqBodyKey = ByteArray(16).also { rng.nextBytes(it) }
    val reqBodyIv = ByteArray(16).also { rng.nextBytes(it) }
    val respAuth = (rng.nextInt(255) + 1).toByte()

    val securityByte: Int =
      when (config.cipher.lowercase().trim()) {
        "none", "zero" -> 0x05 // None
        "chacha20-poly1305", "chacha20-ietf-poly1305" -> 0x03 // Use AES-128-GCM for universal hardware accel
        else -> 0x03 // AES-128-GCM (default for "auto" and "aes-128-gcm")
      }

    // Build VMess Request Header
    val paddingLen = rng.nextInt(16)
    val plainHeader = ByteArrayOutputStream(128)
    plainHeader.write(0x01) // Version = 1
    plainHeader.write(reqBodyIv) // 16-byte Data IV
    plainHeader.write(reqBodyKey) // 16-byte Data Key
    plainHeader.write(respAuth.toInt() and 0xFF) // 1-byte Response Auth
    plainHeader.write(0x01) // Option S (0x01 = standard chunk stream)
    plainHeader.write((paddingLen shl 4) or (securityByte and 0x0F))
    plainHeader.write(0x00) // Reserved
    plainHeader.write(if (isUdp) 0x02 else 0x01) // Command: 0x01 TCP, 0x02 UDP
    plainHeader.write((targetPort ushr 8) and 0xFF)
    plainHeader.write(targetPort and 0xFF)
    writeVmessAddress(plainHeader, targetHost)
    if (paddingLen > 0) {
      val pad = ByteArray(paddingLen).also { rng.nextBytes(it) }
      plainHeader.write(pad)
    }
    val headerWithoutFnv = plainHeader.toByteArray()
    val fnv = fnv1a32(headerWithoutFnv)
    plainHeader.write((fnv ushr 24) and 0xFF)
    plainHeader.write((fnv ushr 16) and 0xFF)
    plainHeader.write((fnv ushr 8) and 0xFF)
    plainHeader.write(fnv and 0xFF)
    val fullPlainHeader = plainHeader.toByteArray()

    // Seal VMess AEAD Header
    val aeadWireHeader = sealVmessAeadHeader(cmdKey, fullPlainHeader)

    val respKey = md5(reqBodyKey)
    val respIv = md5(reqBodyIv)

    val vmessOut =
      object : FilterOutputStream(output) {
        private var headerSent = false
        private var chunkCounter = 0

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          val outBuf = ByteArrayOutputStream(len + aeadWireHeader.size + 64)
          if (!headerSent) {
            headerSent = true
            outBuf.write(aeadWireHeader)
          }
          var pos = off
          var remaining = len
          while (remaining > 0) {
            val sliceLen = minOf(remaining, 16384)
            val plainSlice = b.copyOfRange(pos, pos + sliceLen)
            if (securityByte == 0x05) {
              outBuf.write((sliceLen ushr 8) and 0xFF)
              outBuf.write(sliceLen and 0xFF)
              outBuf.write(plainSlice)
            } else {
              val nonce = buildVmessGcmNonce(chunkCounter++, reqBodyIv)
              val encrypted = aesGcmEncrypt(reqBodyKey, nonce, plainSlice, null)
              outBuf.write((encrypted.size ushr 8) and 0xFF)
              outBuf.write(encrypted.size and 0xFF)
              outBuf.write(encrypted)
            }
            pos += sliceLen
            remaining -= sliceLen
          }
          out.write(outBuf.toByteArray())
          out.flush()
        }
      }

    val vmessIn =
      object : FilterInputStream(input) {
        private val dataIn = DataInputStream(input)
        private var respHeaderParsed = false
        private var respChunkCounter = 0
        private var currentChunk: ByteArray = ByteArray(0)
        private var currentOffset = 0

        @Synchronized
        private fun ensureResponseHeader() {
          if (respHeaderParsed) return
          val lenKey = vmessKdf(respKey, "AEAD Resp Header Len Key").copyOf(16)
          val lenIv = vmessKdf(respIv, "AEAD Resp Header Len IV").copyOf(12)
          val encLenBytes = ByteArray(18)
          dataIn.readFully(encLenBytes)
          val decLenBytes = aesGcmDecrypt(lenKey, lenIv, encLenBytes, null)
          val headerLen = ((decLenBytes[0].toInt() and 0xFF) shl 8) or (decLenBytes[1].toInt() and 0xFF)

          val payloadKey = vmessKdf(respKey, "AEAD Resp Header Key").copyOf(16)
          val payloadIv = vmessKdf(respIv, "AEAD Resp Header IV").copyOf(12)
          val encHeader = ByteArray(headerLen + 16)
          dataIn.readFully(encHeader)
          val decHeader = aesGcmDecrypt(payloadKey, payloadIv, encHeader, null)
          if (decHeader.isEmpty() || decHeader[0] != respAuth) {
            throw IOException("VMess response auth mismatch")
          }
          respHeaderParsed = true
        }

        private fun readNextChunk(): Boolean {
          ensureResponseHeader()
          val b0 = `in`.read()
          if (b0 == -1) return false
          val b1 = `in`.read()
          if (b1 == -1) return false
          val chunkLen = ((b0 and 0xFF) shl 8) or (b1 and 0xFF)
          if (securityByte == 0x05) {
            if (chunkLen == 0) return false
            val buf = ByteArray(chunkLen)
            dataIn.readFully(buf)
            currentChunk = buf
            currentOffset = 0
            return true
          } else {
            if (chunkLen == 16) {
              // Final empty EOF tag chunk
              val eofTag = ByteArray(16)
              dataIn.readFully(eofTag)
              return false
            }
            if (chunkLen < 16) throw IOException("Invalid VMess GCM chunk length: $chunkLen")
            val cipherBytes = ByteArray(chunkLen)
            dataIn.readFully(cipherBytes)
            val nonce = buildVmessGcmNonce(respChunkCounter++, respIv)
            currentChunk = aesGcmDecrypt(respKey, nonce, cipherBytes, null)
            currentOffset = 0
            return currentChunk.isNotEmpty()
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
          while (currentOffset >= currentChunk.size) {
            if (!readNextChunk()) return -1
          }
          val n = minOf(len, currentChunk.size - currentOffset)
          System.arraycopy(currentChunk, currentOffset, b, off, n)
          currentOffset += n
          return n
        }
      }

    return V2RayOutboundClient.TunnelConnection(socket, vmessIn, vmessOut, tlsSocket)
  }

  private fun computeVmessCmdKey(uuidBytes: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("MD5")
    md.update(uuidBytes)
    md.update(VMESS_CMD_KEY_SALT)
    return md.digest()
  }

  private fun sealVmessAeadHeader(cmdKey: ByteArray, plainHeader: ByteArray): ByteArray {
    val authId = createVmessAuthId(cmdKey, System.currentTimeMillis() / 1000L)
    val connectionNonce = ByteArray(8).also { rng.nextBytes(it) }

    val lengthPlain =
      byteArrayOf(
        ((plainHeader.size ushr 8) and 0xFF).toByte(),
        (plainHeader.size and 0xFF).toByte(),
      )
    val lenKey =
      vmessKdf(
        cmdKey,
        "VMess Header AEAD Key_Length",
        String(authId, Charsets.ISO_8859_1),
        String(connectionNonce, Charsets.ISO_8859_1),
      ).copyOf(16)
    val lenNonce =
      vmessKdf(
        cmdKey,
        "VMess Header AEAD Nonce_Length",
        String(authId, Charsets.ISO_8859_1),
        String(connectionNonce, Charsets.ISO_8859_1),
      ).copyOf(12)
    val encryptedLength = aesGcmEncrypt(lenKey, lenNonce, lengthPlain, authId)

    val payloadKey =
      vmessKdf(
        cmdKey,
        "VMess Header AEAD Key",
        String(authId, Charsets.ISO_8859_1),
        String(connectionNonce, Charsets.ISO_8859_1),
      ).copyOf(16)
    val payloadNonce =
      vmessKdf(
        cmdKey,
        "VMess Header AEAD Nonce",
        String(authId, Charsets.ISO_8859_1),
        String(connectionNonce, Charsets.ISO_8859_1),
      ).copyOf(12)
    val encryptedHeader = aesGcmEncrypt(payloadKey, payloadNonce, plainHeader, authId)

    val out = ByteArrayOutputStream(16 + encryptedLength.size + 8 + encryptedHeader.size)
    out.write(authId)
    out.write(encryptedLength)
    out.write(connectionNonce)
    out.write(encryptedHeader)
    return out.toByteArray()
  }

  private fun createVmessAuthId(cmdKey: ByteArray, timeSec: Long): ByteArray {
    val buf = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
    buf.putLong(timeSec)
    val rand4 = ByteArray(4).also { rng.nextBytes(it) }
    buf.put(rand4)
    val crc = CRC32()
    crc.update(buf.array(), 0, 12)
    buf.putInt(crc.value.toInt())
    val aesKey = vmessKdf(cmdKey, "AES Auth ID Encryption").copyOf(16)
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
    return cipher.doFinal(buf.array())
  }

  /**
   * Implements Xray's nested HMAC-based `vmessKdf` (`crypto/vmess/aead/kdf.go`).
   */
  internal fun vmessKdf(key: ByteArray, vararg path: String): ByteArray {
    val pathBytes = ArrayList<ByteArray>(path.size + 1)
    pathBytes.add("VMess AEAD KDF".toByteArray(Charsets.ISO_8859_1))
    for (p in path) {
      pathBytes.add(p.toByteArray(Charsets.ISO_8859_1))
    }

    fun hmacIter(depth: Int, k: ByteArray, msg: ByteArray): ByteArray {
      val ipad = ByteArray(64)
      val opad = ByteArray(64)
      val hashedKey =
        if (k.size > 64) {
          if (depth == 0) sha256(k) else hmacIter(depth - 1, pathBytes[depth - 1], k)
        } else {
          k
        }
      System.arraycopy(hashedKey, 0, ipad, 0, hashedKey.size)
      System.arraycopy(hashedKey, 0, opad, 0, hashedKey.size)
      for (i in 0 until 64) {
        ipad[i] = (ipad[i].toInt() xor 0x36).toByte()
        opad[i] = (opad[i].toInt() xor 0x5C).toByte()
      }
      val innerInput = ByteArray(64 + msg.size)
      System.arraycopy(ipad, 0, innerInput, 0, 64)
      System.arraycopy(msg, 0, innerInput, 64, msg.size)
      val innerHash =
        if (depth == 0) sha256(innerInput) else hmacIter(depth - 1, pathBytes[depth - 1], innerInput)

      val outerInput = ByteArray(64 + innerHash.size)
      System.arraycopy(opad, 0, outerInput, 0, 64)
      System.arraycopy(innerHash, 0, outerInput, 64, innerHash.size)
      return if (depth == 0) sha256(outerInput) else hmacIter(depth - 1, pathBytes[depth - 1], outerInput)
    }

    return hmacIter(pathBytes.size, pathBytes.last(), key)
  }

  private fun buildVmessGcmNonce(count: Int, iv16: ByteArray): ByteArray {
    val nonce = ByteArray(12)
    nonce[0] = ((count ushr 8) and 0xFF).toByte()
    nonce[1] = (count and 0xFF).toByte()
    System.arraycopy(iv16, 2, nonce, 2, 10)
    return nonce
  }

  private fun writeVmessAddress(out: ByteArrayOutputStream, host: String) {
    val ipv4 = V2RayOutboundClient.parseIpv4Bytes(host)
    if (ipv4 != null) {
      out.write(0x01)
      out.write(ipv4)
      return
    }
    val ipv6 = V2RayOutboundClient.parseIpv6Bytes(host)
    if (ipv6 != null && ipv6.size == 16) {
      out.write(0x03)
      out.write(ipv6)
      return
    }
    val domainBytes = host.toByteArray(Charsets.UTF_8)
    out.write(0x02)
    out.write(domainBytes.size)
    out.write(domainBytes)
  }

  private fun fnv1a32(data: ByteArray): Int {
    var hash = 0x811c9dc5.toInt()
    for (b in data) {
      hash = hash xor (b.toInt() and 0xFF)
      hash *= 0x01000193
    }
    return hash
  }

  // ============================================================================
  // 2. Shadowsocks AEAD & Shadowsocks 2022 Outbound Protocol (TCP & UDP)
  // ============================================================================

  fun setupShadowsocksStream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): V2RayOutboundClient.TunnelConnection {
    val method = config.cipher.ifBlank { config.authId.substringBefore(":") }.lowercase().trim()
    val password = config.authId.substringAfter(":", config.authId).trim()

    val is2022 = method.startsWith("2022-blake3-")
    val keySize =
      when {
        method.contains("128") -> 16
        else -> 32
      }
    val saltSize = keySize
    val useChaCha = method.contains("chacha20")

    val masterKey =
      if (is2022) {
        V2RayConfigParser.decodeBase64BytesSafe(password)?.takeIf { it.size >= keySize }?.copyOf(keySize)
          ?: deriveEvpBytesToKey(password, keySize)
      } else {
        deriveEvpBytesToKey(password, keySize)
      }

    val clientSalt = ByteArray(saltSize).also { rng.nextBytes(it) }
    val clientSubkey =
      if (is2022) {
        blake3DeriveKey("shadowsocks 2022 session subkey", masterKey + clientSalt, keySize)
      } else {
        hkdfSha1(masterKey, clientSalt, SS_SUBKEY_INFO, keySize)
      }

    // Build target SOCKS5 address payload
    val addrBuf = ByteArrayOutputStream(64)
    if (is2022) {
      // SS-2022 fixed-length request header + variable-length header
      val nowSec = System.currentTimeMillis() / 1000L
      val varHdr = ByteArrayOutputStream(64)
      writeSocks5TargetAddress(varHdr, targetHost, targetPort)
      varHdr.write(0x00) // 2-byte padding len = 0
      varHdr.write(0x00)
      val varHdrBytes = varHdr.toByteArray()

      val fixedHdr = ByteBuffer.allocate(11).order(ByteOrder.BIG_ENDIAN)
      fixedHdr.put(0x00) // ClientStreamHeaderType = 0
      fixedHdr.putLong(nowSec)
      fixedHdr.putShort(varHdrBytes.size.toShort())
      addrBuf.write(fixedHdr.array())
      addrBuf.write(varHdrBytes)
    } else {
      writeSocks5TargetAddress(addrBuf, targetHost, targetPort)
    }
    val targetHeaderBytes = addrBuf.toByteArray()

    val ssOut =
      object : FilterOutputStream(output) {
        private var firstWrite = true
        private var nonceCounter = 0L

        private fun nextNonce(): ByteArray {
          val nonce = ByteArray(12)
          var c = nonceCounter++
          for (i in 0 until 8) {
            nonce[i] = (c and 0xFF).toByte()
            c = c ushr 8
          }
          return nonce
        }

        private fun sealAead(plain: ByteArray): ByteArray {
          val nonce = nextNonce()
          return if (useChaCha) {
            ChaCha20Poly1305Pure.encrypt(clientSubkey, nonce, plain, ByteArray(0))
          } else {
            aesGcmEncrypt(clientSubkey, nonce, plain, null)
          }
        }

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (len <= 0) return
          val wire = ByteArrayOutputStream(len + 128)
          if (firstWrite) {
            firstWrite = false
            wire.write(clientSalt)
            if (is2022) {
              // Fixed header (11B) + Variable header (with initial payload)
              val fixedPart = targetHeaderBytes.copyOfRange(0, 11)
              val varPart = targetHeaderBytes.copyOfRange(11, targetHeaderBytes.size)
              val combinedVar = ByteArray(varPart.size + minOf(len, 8192))
              System.arraycopy(varPart, 0, combinedVar, 0, varPart.size)
              val initialTake = minOf(len, 8192)
              System.arraycopy(b, off, combinedVar, varPart.size, initialTake)
              // Update length in fixedPart[9..10]
              fixedPart[9] = ((combinedVar.size ushr 8) and 0xFF).toByte()
              fixedPart[10] = (combinedVar.size and 0xFF).toByte()
              wire.write(sealAead(fixedPart))
              wire.write(sealAead(combinedVar))
              if (len > initialTake) {
                writeChunks(wire, b, off + initialTake, len - initialTake)
              }
              out.write(wire.toByteArray())
              out.flush()
              return
            } else {
              val initialTake = minOf(len, 16383 - targetHeaderBytes.size)
              val combined = ByteArray(targetHeaderBytes.size + initialTake)
              System.arraycopy(targetHeaderBytes, 0, combined, 0, targetHeaderBytes.size)
              System.arraycopy(b, off, combined, targetHeaderBytes.size, initialTake)
              writeSingleAeadChunk(wire, combined)
              if (len > initialTake) {
                writeChunks(wire, b, off + initialTake, len - initialTake)
              }
              out.write(wire.toByteArray())
              out.flush()
              return
            }
          }
          writeChunks(wire, b, off, len)
          out.write(wire.toByteArray())
          out.flush()
        }

        private fun writeChunks(wire: ByteArrayOutputStream, b: ByteArray, off: Int, len: Int) {
          var pos = off
          var rem = len
          while (rem > 0) {
            val take = minOf(rem, 0x3FFF)
            writeSingleAeadChunk(wire, b.copyOfRange(pos, pos + take))
            pos += take
            rem -= take
          }
        }

        private fun writeSingleAeadChunk(wire: ByteArrayOutputStream, chunkPlain: ByteArray) {
          val lenBytes =
            byteArrayOf(
              ((chunkPlain.size ushr 8) and 0x3F).toByte(),
              (chunkPlain.size and 0xFF).toByte(),
            )
          wire.write(sealAead(lenBytes))
          wire.write(sealAead(chunkPlain))
        }
      }

    val ssIn =
      object : FilterInputStream(input) {
        private val dataIn = DataInputStream(input)
        private var serverSubkey: ByteArray? = null
        private var nonceCounter = 0L
        private var currentChunk: ByteArray = ByteArray(0)
        private var currentOffset = 0

        private fun nextNonce(): ByteArray {
          val nonce = ByteArray(12)
          var c = nonceCounter++
          for (i in 0 until 8) {
            nonce[i] = (c and 0xFF).toByte()
            c = c ushr 8
          }
          return nonce
        }

        private fun openAead(subkey: ByteArray, cipherWithTag: ByteArray): ByteArray {
          val nonce = nextNonce()
          return if (useChaCha) {
            ChaCha20Poly1305Pure.decrypt(subkey, nonce, cipherWithTag, ByteArray(0))
          } else {
            aesGcmDecrypt(subkey, nonce, cipherWithTag, null)
          }
        }

        private fun readNextChunk(): Boolean {
          var subkey = serverSubkey
          if (subkey == null) {
            val serverSalt = ByteArray(saltSize)
            val firstByte = `in`.read()
            if (firstByte == -1) return false
            serverSalt[0] = firstByte.toByte()
            dataIn.readFully(serverSalt, 1, saltSize - 1)
            subkey =
              if (is2022) {
                blake3DeriveKey("shadowsocks 2022 session subkey", masterKey + serverSalt, keySize)
              } else {
                hkdfSha1(masterKey, serverSalt, SS_SUBKEY_INFO, keySize)
              }
            serverSubkey = subkey
            if (is2022) {
              // Read SS-2022 response fixed header (1 + 8 + saltSize + 2 = 11 + saltSize bytes + 16B tag)
              val fixedEnc = ByteArray(11 + saltSize + 16)
              dataIn.readFully(fixedEnc)
              val fixedDec = openAead(subkey, fixedEnc)
              val firstLen =
                ((fixedDec[fixedDec.size - 2].toInt() and 0xFF) shl 8) or
                  (fixedDec[fixedDec.size - 1].toInt() and 0xFF)
              val firstDataEnc = ByteArray(firstLen + 16)
              dataIn.readFully(firstDataEnc)
              currentChunk = openAead(subkey, firstDataEnc)
              currentOffset = 0
              return currentChunk.isNotEmpty()
            }
          }

          val encLen = ByteArray(2 + 16)
          val b0 = `in`.read()
          if (b0 == -1) return false
          encLen[0] = b0.toByte()
          dataIn.readFully(encLen, 1, encLen.size - 1)
          val decLen = openAead(subkey, encLen)
          val payloadLen = ((decLen[0].toInt() and 0x3F) shl 8) or (decLen[1].toInt() and 0xFF)
          if (payloadLen <= 0) return false
          val encPayload = ByteArray(payloadLen + 16)
          dataIn.readFully(encPayload)
          currentChunk = openAead(subkey, encPayload)
          currentOffset = 0
          return currentChunk.isNotEmpty()
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
          while (currentOffset >= currentChunk.size) {
            if (!readNextChunk()) return -1
          }
          val n = minOf(len, currentChunk.size - currentOffset)
          System.arraycopy(currentChunk, currentOffset, b, off, n)
          currentOffset += n
          return n
        }
      }

    return V2RayOutboundClient.TunnelConnection(socket, ssIn, ssOut, tlsSocket)
  }

  fun exchangeShadowsocksUdpDatagram(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    udpPayload: ByteArray,
    timeoutMs: Int = 3000,
    udpProtector: ((DatagramSocket) -> Boolean)? = null,
  ): ByteArray? {
    val method = config.cipher.ifBlank { config.authId.substringBefore(":") }.lowercase().trim()
    if (method.startsWith("2022-")) return null
    val password = config.authId.substringAfter(":", config.authId).trim()
    val keySize = if (method.contains("128")) 16 else 32
    val useChaCha = method.contains("chacha20")
    val masterKey = deriveEvpBytesToKey(password, keySize)
    val salt = ByteArray(keySize).also { rng.nextBytes(it) }
    val subkey = hkdfSha1(masterKey, salt, SS_SUBKEY_INFO, keySize)

    val plainOut = ByteArrayOutputStream(udpPayload.size + 64)
    writeSocks5TargetAddress(plainOut, targetHost, targetPort)
    plainOut.write(udpPayload)
    val zeroNonce = ByteArray(12)
    val encrypted =
      if (useChaCha) {
        ChaCha20Poly1305Pure.encrypt(subkey, zeroNonce, plainOut.toByteArray(), ByteArray(0))
      } else {
        aesGcmEncrypt(subkey, zeroNonce, plainOut.toByteArray(), null)
      }
    val packetBytes = salt + encrypted

    return try {
      DatagramSocket().use { sock ->
        udpProtector?.invoke(sock)
        sock.soTimeout = timeoutMs
        val serverIp =
          config.resolvedIp.ifBlank { V2RayOutboundClient.resolveEndpointIpv4(config.address) ?: config.address }
        val serverAddr = InetAddress.getByName(serverIp)
        sock.send(DatagramPacket(packetBytes, packetBytes.size, serverAddr, config.port))
        val recvBuf = ByteArray(65507)
        val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
        sock.receive(recvPkt)
        if (recvPkt.length <= keySize + 16 + 7) return null
        val respSalt = recvBuf.copyOfRange(0, keySize)
        val respCipher = recvBuf.copyOfRange(keySize, recvPkt.length)
        val respSubkey = hkdfSha1(masterKey, respSalt, SS_SUBKEY_INFO, keySize)
        val dec =
          if (useChaCha) {
            ChaCha20Poly1305Pure.decrypt(respSubkey, zeroNonce, respCipher, ByteArray(0))
          } else {
            aesGcmDecrypt(respSubkey, zeroNonce, respCipher, null)
          }
        stripSocks5AddressHeader(dec)
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun stripSocks5AddressHeader(data: ByteArray): ByteArray? {
    if (data.size < 7) return null
    val atyp = data[0].toInt() and 0xFF
    val headerLen =
      when (atyp) {
        0x01 -> 1 + 4 + 2
        0x03 -> 1 + 1 + (data[1].toInt() and 0xFF) + 2
        0x04 -> 1 + 16 + 2
        else -> return null
      }
    if (data.size <= headerLen) return null
    return data.copyOfRange(headerLen, data.size)
  }

  // ============================================================================
  // 3. Direct SOCKS5 & HTTP CONNECT Proxy Outbound Protocols
  // ============================================================================

  fun setupSocks5Stream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): V2RayOutboundClient.TunnelConnection {
    val dataIn = DataInputStream(input)
    val hasAuth = config.authId.contains(":")
    if (hasAuth) {
      output.write(byteArrayOf(0x05, 0x02, 0x00, 0x02))
    } else {
      output.write(byteArrayOf(0x05, 0x01, 0x00))
    }
    output.flush()

    val methodReply = ByteArray(2)
    dataIn.readFully(methodReply)
    if (methodReply[0].toInt() != 0x05) {
      throw IOException("Invalid SOCKS5 version: ${methodReply[0]}")
    }
    val chosenMethod = methodReply[1].toInt() and 0xFF
    if (chosenMethod == 0x02) {
      val user = config.authId.substringBefore(":").toByteArray(Charsets.UTF_8)
      val pass = config.authId.substringAfter(":").toByteArray(Charsets.UTF_8)
      val authReq = ByteArrayOutputStream(3 + user.size + pass.size)
      authReq.write(0x01)
      authReq.write(user.size)
      authReq.write(user)
      authReq.write(pass.size)
      authReq.write(pass)
      output.write(authReq.toByteArray())
      output.flush()
      val authReply = ByteArray(2)
      dataIn.readFully(authReply)
      if (authReply[1].toInt() != 0x00) {
        throw IOException("SOCKS5 authentication failed")
      }
    } else if (chosenMethod != 0x00) {
      throw IOException("Unsupported SOCKS5 auth method: $chosenMethod")
    }

    val connectReq = ByteArrayOutputStream(64)
    connectReq.write(byteArrayOf(0x05, 0x01, 0x00)) // VER=5, CMD=CONNECT(1), RSV=0
    writeSocks5TargetAddress(connectReq, targetHost, targetPort)
    output.write(connectReq.toByteArray())
    output.flush()

    val respHead = ByteArray(4)
    dataIn.readFully(respHead)
    if (respHead[1].toInt() != 0x00) {
      throw IOException("SOCKS5 CONNECT failed with code ${respHead[1]}")
    }
    val bindSkip =
      when (respHead[3].toInt() and 0xFF) {
        0x01 -> 4 + 2
        0x03 -> {
          val dLen = input.read()
          if (dLen < 0) throw EOFException("SOCKS5 EOF reading domain")
          dLen + 2
        }
        0x04 -> 16 + 2
        else -> throw IOException("Unknown SOCKS5 ATYP: ${respHead[3]}")
      }
    dataIn.readFully(ByteArray(bindSkip))
    return V2RayOutboundClient.TunnelConnection(socket, input, output, tlsSocket)
  }

  fun setupHttpProxyStream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
  ): V2RayOutboundClient.TunnelConnection {
    val authHeader =
      if (config.authId.isNotBlank()) {
        val b64 =
          java.util.Base64.getEncoder().encodeToString(config.authId.toByteArray(Charsets.UTF_8))
        "Proxy-Authorization: Basic $b64\r\n"
      } else {
        ""
      }
    val req =
      "CONNECT $targetHost:$targetPort HTTP/1.1\r\n" +
        "Host: $targetHost:$targetPort\r\n" +
        "User-Agent: ${GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT}\r\n" +
        "Proxy-Connection: keep-alive\r\n" +
        authHeader +
        "\r\n"
    output.write(req.toByteArray(Charsets.US_ASCII))
    output.flush()

    val respBuf = ByteArrayOutputStream(256)
    var state = 0
    while (respBuf.size() < 8192) {
      val b = input.read()
      if (b == -1) throw EOFException("EOF during HTTP CONNECT proxy handshake")
      respBuf.write(b)
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
    val statusLine = respBuf.toString("US-ASCII").lineSequence().firstOrNull().orEmpty()
    if (!statusLine.contains(" 200 ")) {
      throw IOException("HTTP CONNECT proxy rejected request: $statusLine")
    }
    return V2RayOutboundClient.TunnelConnection(socket, input, output, tlsSocket)
  }

  // ============================================================================
  // Cryptographic Helpers (AES-GCM, EVP_BytesToKey, HKDF-SHA1, BLAKE3, ChaCha20-Poly1305)
  // ============================================================================

  internal fun writeSocks5TargetAddress(out: ByteArrayOutputStream, host: String, port: Int) {
    val ipv4 = V2RayOutboundClient.parseIpv4Bytes(host)
    if (ipv4 != null) {
      out.write(0x01)
      out.write(ipv4)
    } else {
      val ipv6 = V2RayOutboundClient.parseIpv6Bytes(host)
      if (ipv6 != null && ipv6.size == 16) {
        out.write(0x04)
        out.write(ipv6)
      } else {
        val domainBytes = host.toByteArray(Charsets.UTF_8)
        out.write(0x03)
        out.write(domainBytes.size)
        out.write(domainBytes)
      }
    }
    out.write((port ushr 8) and 0xFF)
    out.write(port and 0xFF)
  }

  internal fun aesGcmEncrypt(
    key: ByteArray,
    nonce12: ByteArray,
    plain: ByteArray,
    aad: ByteArray?,
  ): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce12))
    if (aad != null && aad.isNotEmpty()) {
      cipher.updateAAD(aad)
    }
    return cipher.doFinal(plain)
  }

  internal fun aesGcmDecrypt(
    key: ByteArray,
    nonce12: ByteArray,
    cipherWithTag: ByteArray,
    aad: ByteArray?,
  ): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce12))
    if (aad != null && aad.isNotEmpty()) {
      cipher.updateAAD(aad)
    }
    return cipher.doFinal(cipherWithTag)
  }

  internal fun deriveEvpBytesToKey(password: String, keyLen: Int): ByteArray {
    val passBytes = password.toByteArray(Charsets.UTF_8)
    val result = ByteArrayOutputStream(keyLen + 16)
    var prev = ByteArray(0)
    while (result.size() < keyLen) {
      val md = MessageDigest.getInstance("MD5")
      md.update(prev)
      md.update(passBytes)
      prev = md.digest()
      result.write(prev)
    }
    return result.toByteArray().copyOf(keyLen)
  }

  internal fun hkdfSha1(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(SecretKeySpec(salt, "HmacSHA1"))
    val prk = mac.doFinal(ikm)
    mac.init(SecretKeySpec(prk, "HmacSHA1"))
    val okm = ByteArrayOutputStream(outLen + 20)
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

  private fun md5(input: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(input)
  private fun sha256(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(input)

  /**
   * Pure-Kotlin BLAKE3 `derive_key` implementation for Shadowsocks-2022 (`2022-blake3-*`).
   */
  internal fun blake3DeriveKey(context: String, keyMaterial: ByteArray, outLen: Int): ByteArray {
    val iv =
      intArrayOf(
        0x6A09E667,
        -0x4498517b,
        0x3C6EF372,
        -0x5ab00ac6,
        0x510E527F,
        -0x64fa9774,
        0x1F83D9AB,
        0x5BE0CD19,
      )
    val ctxBytes = context.toByteArray(Charsets.UTF_8)
    val contextKeyWords = blake3CompressWords(iv, ctxBytes, 0L, ctxBytes.size, 1 or 2 or 8 or 32)
    return blake3HashWithKey(contextKeyWords, keyMaterial, outLen, 64)
  }

  private fun blake3HashWithKey(
    keyWords: IntArray,
    input: ByteArray,
    outLen: Int,
    baseFlags: Int,
  ): ByteArray {
    var cv = keyWords.copyOf(8)
    val blocks = if (input.isEmpty()) 1 else (input.size + 63) / 64
    val out = ByteArray(outLen)
    for (bIdx in 0 until blocks) {
      val start = bIdx * 64
      val end = minOf(input.size, start + 64)
      val blockBytes = input.copyOfRange(start, end)
      var flags = baseFlags
      if (bIdx == 0) flags = flags or 1
      val isLast = bIdx == blocks - 1
      if (isLast) {
        flags = flags or 2 or 8
        var outPos = 0
        var counter = 0L
        while (outPos < outLen) {
          val words = blake3CompressFull(cv, blockBytes, counter++, blockBytes.size, flags)
          val bb = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
          for (w in words) bb.putInt(w)
          val arr = bb.array()
          val take = minOf(64, outLen - outPos)
          System.arraycopy(arr, 0, out, outPos, take)
          outPos += take
        }
      } else {
        cv = blake3CompressWords(cv, blockBytes, 0L, 64, flags)
      }
    }
    return out
  }

  private val BLAKE3_PERM =
    intArrayOf(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

  private fun blake3CompressWords(
    cv: IntArray,
    block: ByteArray,
    counter: Long,
    blockLen: Int,
    flags: Int,
  ): IntArray = blake3CompressFull(cv, block, counter, blockLen, flags).copyOf(8)

  private fun blake3CompressFull(
    cv: IntArray,
    block: ByteArray,
    counter: Long,
    blockLen: Int,
    flags: Int,
  ): IntArray {
    val padded = ByteArray(64)
    System.arraycopy(block, 0, padded, 0, minOf(block.size, 64))
    val m = IntArray(16)
    val bb = ByteBuffer.wrap(padded).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 16) m[i] = bb.int

    val v =
      intArrayOf(
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        0x6A09E667, -0x4498517b, 0x3C6EF372, -0x5ab00ac6,
        counter.toInt(), (counter ushr 32).toInt(), blockLen, flags,
      )

    fun g(a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
      v[a] = v[a] + v[b] + mx
      v[d] = Integer.rotateRight(v[d] xor v[a], 16)
      v[c] = v[c] + v[d]
      v[b] = Integer.rotateRight(v[b] xor v[c], 12)
      v[a] = v[a] + v[b] + my
      v[d] = Integer.rotateRight(v[d] xor v[a], 8)
      v[c] = v[c] + v[d]
      v[b] = Integer.rotateRight(v[b] xor v[c], 7)
    }

    for (round in 0 until 7) {
      g(0, 4, 8, 12, m[0], m[1])
      g(1, 5, 9, 13, m[2], m[3])
      g(2, 6, 10, 14, m[4], m[5])
      g(3, 7, 11, 15, m[6], m[7])
      g(0, 5, 10, 15, m[8], m[9])
      g(1, 6, 11, 12, m[10], m[11])
      g(2, 7, 8, 13, m[12], m[13])
      g(3, 4, 9, 14, m[14], m[15])
      if (round < 6) {
        val nextM = IntArray(16)
        for (i in 0 until 16) nextM[i] = m[BLAKE3_PERM[i]]
        System.arraycopy(nextM, 0, m, 0, 16)
      }
    }
    for (i in 0 until 8) {
      v[i] = v[i] xor v[i + 8]
      v[i + 8] = v[i + 8] xor cv[i]
    }
    return v
  }
}

/**
 * RFC 8439 ChaCha20-Poly1305 AEAD implementation compatible with all Android API levels (API 21+).
 */
internal object ChaCha20Poly1305Pure {

  fun encrypt(key32: ByteArray, nonce12: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
    return try {
      val cipher = Cipher.getInstance("ChaCha20-Poly1305")
      cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "ChaCha20"), javax.crypto.spec.IvParameterSpec(nonce12))
      if (aad.isNotEmpty()) cipher.updateAAD(aad)
      cipher.doFinal(plaintext)
    } catch (_: Exception) {
      encryptSoftware(key32, nonce12, plaintext, aad)
    }
  }

  fun decrypt(key32: ByteArray, nonce12: ByteArray, cipherWithTag: ByteArray, aad: ByteArray): ByteArray {
    return try {
      val cipher = Cipher.getInstance("ChaCha20-Poly1305")
      cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "ChaCha20"), javax.crypto.spec.IvParameterSpec(nonce12))
      if (aad.isNotEmpty()) cipher.updateAAD(aad)
      cipher.doFinal(cipherWithTag)
    } catch (_: Exception) {
      decryptSoftware(key32, nonce12, cipherWithTag, aad)
    }
  }

  private fun encryptSoftware(key: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray): ByteArray {
    val polyKey = chacha20Block(key, 0, nonce).copyOf(32)
    val cipherText = chacha20Xor(key, 1, nonce, plain)
    val tag = poly1305Mac(polyKey, buildPoly1305Input(aad, cipherText))
    return cipherText + tag
  }

  private fun decryptSoftware(key: ByteArray, nonce: ByteArray, cipherWithTag: ByteArray, aad: ByteArray): ByteArray {
    if (cipherWithTag.size < 16) throw IOException("ChaCha20-Poly1305 ciphertext too short")
    val cipherText = cipherWithTag.copyOfRange(0, cipherWithTag.size - 16)
    val receivedTag = cipherWithTag.copyOfRange(cipherWithTag.size - 16, cipherWithTag.size)
    val polyKey = chacha20Block(key, 0, nonce).copyOf(32)
    val expectedTag = poly1305Mac(polyKey, buildPoly1305Input(aad, cipherText))
    if (!MessageDigest.isEqual(receivedTag, expectedTag)) {
      throw IOException("ChaCha20-Poly1305 authentication tag mismatch")
    }
    return chacha20Xor(key, 1, nonce, cipherText)
  }

  private fun chacha20Xor(key: ByteArray, initialCounter: Int, nonce: ByteArray, input: ByteArray): ByteArray {
    val out = ByteArray(input.size)
    var counter = initialCounter
    var pos = 0
    while (pos < input.size) {
      val block = chacha20Block(key, counter++, nonce)
      val take = minOf(64, input.size - pos)
      for (i in 0 until take) {
        out[pos + i] = (input[pos + i].toInt() xor block[i].toInt()).toByte()
      }
      pos += take
    }
    return out
  }

  private fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
    val state = IntArray(16)
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574
    val kb = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 8) state[4 + i] = kb.int
    state[12] = counter
    val nb = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 3) state[13 + i] = nb.int

    val w = state.copyOf()
    fun qr(a: Int, b: Int, c: Int, d: Int) {
      w[a] += w[b]; w[d] = Integer.rotateLeft(w[d] xor w[a], 16)
      w[c] += w[d]; w[b] = Integer.rotateLeft(w[b] xor w[c], 12)
      w[a] += w[b]; w[d] = Integer.rotateLeft(w[d] xor w[a], 8)
      w[c] += w[d]; w[b] = Integer.rotateLeft(w[b] xor w[c], 7)
    }
    repeat(10) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    }
    val out = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until 16) out.putInt(w[i] + state[i])
    return out.array()
  }

  private fun buildPoly1305Input(aad: ByteArray, cipherText: ByteArray): ByteArray {
    val out = ByteArrayOutputStream(aad.size + cipherText.size + 48)
    out.write(aad)
    if (aad.size % 16 != 0) out.write(ByteArray(16 - (aad.size % 16)))
    out.write(cipherText)
    if (cipherText.size % 16 != 0) out.write(ByteArray(16 - (cipherText.size % 16)))
    val lens = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
    lens.putLong(aad.size.toLong())
    lens.putLong(cipherText.size.toLong())
    out.write(lens.array())
    return out.toByteArray()
  }

  private fun poly1305Mac(key32: ByteArray, msg: ByteArray): ByteArray {
    val rBytes = key32.copyOfRange(0, 16)
    rBytes[3] = (rBytes[3].toInt() and 15).toByte()
    rBytes[7] = (rBytes[7].toInt() and 15).toByte()
    rBytes[11] = (rBytes[11].toInt() and 15).toByte()
    rBytes[15] = (rBytes[15].toInt() and 15).toByte()
    rBytes[4] = (rBytes[4].toInt() and 252).toByte()
    rBytes[8] = (rBytes[8].toInt() and 252).toByte()
    rBytes[12] = (rBytes[12].toInt() and 252).toByte()

    val r = java.math.BigInteger(1, rBytes.reversedArray())
    val s = java.math.BigInteger(1, key32.copyOfRange(16, 32).reversedArray())
    val p = java.math.BigInteger.ONE.shiftLeft(130).subtract(java.math.BigInteger.valueOf(5))
    var acc = java.math.BigInteger.ZERO
    var pos = 0
    while (pos < msg.size) {
      val take = minOf(16, msg.size - pos)
      val blockLe = ByteArray(take + 1)
      for (i in 0 until take) {
        blockLe[take - i] = msg[pos + i]
      }
      blockLe[0] = 0x01
      val n = java.math.BigInteger(1, blockLe)
      acc = acc.add(n).multiply(r).mod(p)
      pos += take
    }
    acc = acc.add(s)
    val raw = acc.toByteArray()
    val tag = ByteArray(16)
    for (i in 0 until 16) {
      val srcIdx = raw.size - 1 - i
      tag[i] = if (srcIdx >= 0) raw[srcIdx] else 0
    }
    return tag
  }
}
