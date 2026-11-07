package com.example.vpn

import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.system.measureNanoTime

/**
 * Real V2Ray Outbound Protocol Client supporting:
 * - Protocols: VLESS (v0 TCP `0x01` & UDP `0x02`), MVLESS (0x96), JVLESS (0x78), Trojan, and Direct Serverless
 * - Transports: Raw TCP, RFC 6455 WebSocket (ws), and HTTPUpgrade (httpupgrade)
 * - Pre-Warmed Transport Pool: Maintains ready TLS + WebSocket connections per active V2Ray node
 *   (before the VLESS/Trojan target header is written) so multi-connection bursts (Instagram, X)
 *   skip the 2-RTT TLS+WS handshake completely.
 * - Smart Strict-First TLS Validation: Validates X.509 certificate chains and SNI hostnames against
 *   the Android system trust store first, falling back to permissive mode only for community nodes
 *   with self-signed/mismatched origin certs.
 */
object V2RayOutboundClient {

  const val VLESS_CMD_TCP: Int = 0x01
  const val VLESS_CMD_UDP: Int = 0x02

  private const val MAX_PREWARMED_PER_NODE = 5
  private const val PREWARMED_MAX_AGE_MS = 22_000L

  private val secureRandom = SecureRandom()

  private val systemTrustManager: X509TrustManager? by lazy {
    try {
      val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
      tmf.init(null as KeyStore?)
      tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
    } catch (_: Exception) {
      null
    }
  }

  val strictSslContext: SSLContext by lazy {
    SSLContext.getInstance("TLS").apply {
      val tm = systemTrustManager
      if (tm != null) {
        init(null, arrayOf<TrustManager>(tm), secureRandom)
      } else {
        init(null, null, secureRandom)
      }
    }
  }

  val permissiveSslContext: SSLContext by lazy {
    val trustAll =
      arrayOf<TrustManager>(
        object : X509TrustManager {
          override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
      )
    SSLContext.getInstance("TLS").apply {
      init(null, trustAll, secureRandom)
    }
  }

  /**
   * Builds an `SSLContext` that performs full system X.509 certificate chain validation and
   * hostname verification when the certificate and [sniHost] are valid, and only falls back to
   * permissive acceptance when [allowInsecureFallback] is true and strict verification fails.
   */
  fun createSmartSslContext(
    sniHost: String,
    allowInsecureFallback: Boolean = true,
  ): SSLContext {
    val cleanSni = sniHost.trim().trimEnd('.').lowercase()
    val defaultTm = systemTrustManager
    if (defaultTm == null) {
      return if (allowInsecureFallback) permissiveSslContext else strictSslContext
    }

    val smartTrustManager =
      object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
          defaultTm.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
          if (chain.isNullOrEmpty()) {
            if (allowInsecureFallback) {
              MehDiag.recordTlsPermissiveFallback()
              return
            }
            throw CertificateException("Empty server certificate chain")
          }
          try {
            defaultTm.checkServerTrusted(chain, authType)
            if (cleanSni.isNotEmpty() && parseIpv4Bytes(cleanSni) == null && !cleanSni.contains(':')) {
              val leaf = chain[0]
              if (!verifyCertificateHostname(cleanSni, leaf)) {
                throw CertificateException("Hostname $cleanSni does not match certificate SAN/CN")
              }
            }
            MehDiag.recordTlsStrictVerified()
          } catch (ce: CertificateException) {
            if (allowInsecureFallback) {
              MehDiag.recordTlsPermissiveFallback()
            } else {
              throw ce
            }
          } catch (e: Exception) {
            if (allowInsecureFallback) {
              MehDiag.recordTlsPermissiveFallback()
            } else {
              throw CertificateException("TLS trust check failed: ${e.message}", e)
            }
          }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = defaultTm.acceptedIssuers
      }

    return SSLContext.getInstance("TLS").apply {
      init(null, arrayOf<TrustManager>(smartTrustManager), secureRandom)
    }
  }

  internal fun verifyCertificateHostname(hostname: String, certificate: X509Certificate): Boolean {
    val cleanHost = hostname.trim().trimEnd('.').lowercase()
    if (cleanHost.isEmpty()) return false
    return try {
      val altNames = certificate.subjectAlternativeNames
      if (altNames != null) {
        for (entry in altNames) {
          if (entry != null && entry.size >= 2) {
            val type = entry[0] as? Int ?: continue
            val value = (entry[1] as? String)?.lowercase()?.trimEnd('.') ?: continue
            if (type == 2 || type == 7) { // dNSName (2) or iPAddress (7)
              if (matchesWildcardPattern(cleanHost, value)) return true
            }
          }
        }
      }
      val subjectPrincipal = certificate.subjectX500Principal?.name.orEmpty()
      val cnMatch =
        Regex("CN=([^,]+)", RegexOption.IGNORE_CASE)
          .find(subjectPrincipal)
          ?.groupValues
          ?.getOrNull(1)
          ?.trim()
          ?.lowercase()
      if (!cnMatch.isNullOrEmpty() && matchesWildcardPattern(cleanHost, cnMatch)) {
        return true
      }
      HttpsURLConnection.getDefaultHostnameVerifier().verify(cleanHost, null)
    } catch (_: Exception) {
      false
    }
  }

  private fun matchesWildcardPattern(hostname: String, pattern: String): Boolean {
    if (hostname == pattern) return true
    if (pattern.startsWith("*.")) {
      val suffix = pattern.removePrefix("*.")
      if (hostname.endsWith(".$suffix")) {
        val prefix = hostname.removeSuffix(".$suffix")
        return !prefix.contains('.') && prefix.isNotEmpty()
      }
    }
    return false
  }

  class TunnelConnection(
    val underlyingSocket: Socket,
    val inputStream: InputStream,
    val outputStream: OutputStream,
    val tlsSocket: SSLSocket? = null,
  ) : AutoCloseable {
    fun setReadTimeout(timeoutMs: Int) {
      try {
        tlsSocket?.soTimeout = timeoutMs
      } catch (_: Exception) {}
      try {
        underlyingSocket.soTimeout = timeoutMs
      } catch (_: Exception) {}
    }

    /**
     * Propagates client write-side closure (`EOF`) to the remote V2Ray node stream so the node
     * closes the upstream target connection promptly instead of keeping it open for 180 seconds.
     */
    fun closeOutbound() {
      try {
        outputStream.flush()
      } catch (_: Exception) {}
      try {
        if (tlsSocket != null) {
          tlsSocket.close()
        } else {
          underlyingSocket.shutdownOutput()
        }
      } catch (_: Exception) {}
    }

    override fun close() {
      try {
        outputStream.close()
      } catch (_: Exception) {}
      try {
        inputStream.close()
      } catch (_: Exception) {}
      try {
        tlsSocket?.close()
      } catch (_: Exception) {}
      try {
        underlyingSocket.close()
      } catch (_: Exception) {}
    }
  }

  /**
   * Represents an already-handshaked TCP + TLS + WebSocket/HTTPUpgrade transport connection to a
   * V2Ray node BEFORE the VLESS/Trojan header is written.
   */
  private data class PrewarmedNodeTransport(
    val rawSocket: Socket,
    val tlsSocket: SSLSocket?,
    val transportIn: InputStream,
    val transportOut: OutputStream,
    val createdAtMs: Long = System.currentTimeMillis(),
  ) {
    fun isHealthy(): Boolean {
      val age = System.currentTimeMillis() - createdAtMs
      if (age > PREWARMED_MAX_AGE_MS) return false
      if (rawSocket.isClosed || !rawSocket.isConnected || rawSocket.isInputShutdown || rawSocket.isOutputShutdown) {
        return false
      }
      if (tlsSocket != null && (tlsSocket.isClosed || !tlsSocket.isConnected)) {
        return false
      }
      return true
    }

    fun closeQuietly() {
      try {
        transportOut.close()
      } catch (_: Exception) {}
      try {
        transportIn.close()
      } catch (_: Exception) {}
      try {
        tlsSocket?.close()
      } catch (_: Exception) {}
      try {
        rawSocket.close()
      } catch (_: Exception) {}
    }
  }

  private val prewarmedPools = ConcurrentHashMap<String, ConcurrentLinkedQueue<PrewarmedNodeTransport>>()
  private val inFlightWarmups = ConcurrentHashMap<String, AtomicInteger>()

  private val warmupExecutor: ExecutorService =
    ThreadPoolExecutor(
      2,
      8,
      30L,
      TimeUnit.SECONDS,
      LinkedBlockingQueue(32),
      { runnable ->
        Thread(runnable, "meh-transport-prewarmer").apply {
          isDaemon = true
        }
      },
      ThreadPoolExecutor.DiscardPolicy(),
    )

  /**
   * Asynchronously pre-warms up to [targetCount] ready TLS+WS connections for [config] so
   * subsequent TCP streams (e.g., Instagram feed images/videos) open in 0 RTT.
   */
  fun warmUpNodePoolAsync(
    config: V2RayConfig,
    protector: ((Socket) -> Boolean)?,
    targetCount: Int = 3,
  ) {
    if (!canUsePrewarmedPool(config)) return
    val key = config.endpointKey
    val queue = prewarmedPools.computeIfAbsent(key) { ConcurrentLinkedQueue() }
    pruneExpiredFromQueue(queue)

    val inFlight = inFlightWarmups.computeIfAbsent(key) { AtomicInteger(0) }
    val currentTotal = queue.size + inFlight.get()
    val needed = (targetCount.coerceAtMost(MAX_PREWARMED_PER_NODE) - currentTotal).coerceAtLeast(0)
    repeat(needed) {
      inFlight.incrementAndGet()
      warmupExecutor.execute {
        try {
          if (queue.size < MAX_PREWARMED_PER_NODE) {
            val transport = dialNodeTransport(config, timeoutMs = 4500, protector = protector)
            queue.offer(transport)
            MehDiag.recordPrewarmedPoolCreated()
          }
        } catch (_: Exception) {
        } finally {
          inFlight.decrementAndGet()
        }
      }
    }
  }

  fun evictPrewarmedTransports(endpointKey: String) {
    prewarmedPools.remove(endpointKey)?.let { queue ->
      while (true) {
        val item = queue.poll() ?: break
        item.closeQuietly()
      }
    }
  }

  fun clearAllPrewarmedTransports() {
    val keys = prewarmedPools.keys.toList()
    for (k in keys) {
      evictPrewarmedTransports(k)
    }
  }

  private fun canUsePrewarmedPool(config: V2RayConfig): Boolean {
    if (config.protocol == V2RayProtocol.SERVERLESS ||
      config.protocol == V2RayProtocol.WIREGUARD ||
      config.protocol == V2RayProtocol.SOCKS5 ||
      config.protocol == V2RayProtocol.HTTP_PROXY ||
      config.network.equals("kcp", ignoreCase = true)
    ) {
      return false
    }
    return isSupportedByEngine(config)
  }

  private fun pruneExpiredFromQueue(queue: ConcurrentLinkedQueue<PrewarmedNodeTransport>) {
    val iter = queue.iterator()
    while (iter.hasNext()) {
      val item = iter.next()
      if (!item.isHealthy()) {
        iter.remove()
        item.closeQuietly()
      }
    }
  }

  private fun pollPrewarmedTransport(config: V2RayConfig): PrewarmedNodeTransport? {
    val queue = prewarmedPools[config.endpointKey] ?: return null
    while (true) {
      val candidate = queue.poll() ?: return null
      if (candidate.isHealthy()) {
        return candidate
      } else {
        candidate.closeQuietly()
      }
    }
  }

  /**
   * Returns true if this config uses a protocol, transport, and security layer supported by our unified engine.
   */
  fun isSupportedByEngine(config: V2RayConfig): Boolean {
    if (config.protocol == V2RayProtocol.SERVERLESS) {
      return true
    }
    if (config.address.contains(":")) {
      return false
    }
    when (config.protocol) {
      V2RayProtocol.SHADOWSOCKS -> {
        val cipher = config.cipher.ifBlank { config.authId.substringBefore(":") }
        return VmessAndShadowsocksEngine.isSupportedShadowsocksCipher(cipher)
      }
      V2RayProtocol.WIREGUARD -> {
        return config.authId.isNotBlank() && config.publicKey.isNotBlank()
      }
      V2RayProtocol.HYSTERIA2,
      V2RayProtocol.TUIC -> {
        return config.authId.isNotBlank()
      }
      V2RayProtocol.SOCKS5,
      V2RayProtocol.HTTP_PROXY -> {
        return config.address.isNotBlank() && config.port in 1..65535
      }
      V2RayProtocol.VMESS -> {
        if (parseUuidBytes(config.authId) == null) return false
      }
      V2RayProtocol.VLESS,
      V2RayProtocol.MVLESS,
      V2RayProtocol.JVLESS -> {
        if (parseUuidBytes(config.authId) == null) return false
        val enc = config.encryption.lowercase().trim()
        if (enc != "none" && enc != "") return false
        val flw = config.flow.lowercase().trim()
        if (flw.isNotEmpty() &&
          flw != "xtls-rprx-vision" &&
          flw != "xtls-rprx-vision-udp443"
        ) {
          return false
        }
      }
      V2RayProtocol.TROJAN -> {
        if (config.authId.isBlank()) return false
      }
      else -> return false
    }

    val net = config.network.lowercase().trim()
    if (net != "tcp" &&
      net != "ws" &&
      net != "httpupgrade" &&
      net != "grpc" &&
      net != "xhttp" &&
      net != "splithttp" &&
      net != "h2" &&
      net != "http" &&
      net != "kcp" &&
      net != "mkcp" &&
      net != "quic" &&
      net != "udp"
    ) {
      return false
    }

    val sec = config.security.lowercase().trim()
    if (sec != "none" &&
      sec != "tls" &&
      sec != "reality" &&
      sec != "ss" &&
      sec != "noise" &&
      sec != ""
    ) {
      return false
    }
    if (sec == "reality" && config.pbk.isBlank()) {
      return false
    }

    val hdr = config.headerType.lowercase().trim()
    if (hdr != "none" && hdr != "http" && hdr != "" && hdr != "---") {
      return false
    }
    return true
  }

  private val resolvedEndpointCache = ConcurrentHashMap<String, String>()

  /**
   * Resolves a V2Ray server hostname to a clean public IPv4 address, rejecting private/sinkhole IPs
   * (such as 10.10.34.x ISP DNS poisoning).
   */
  private val dnsExecutor = Executors.newCachedThreadPool { runnable ->
    Thread(runnable, "meh-dns").apply { isDaemon = true }
  }

  /**
   * System DNS (`InetAddress.getAllByName`) has no timeout and can block a probe thread
   * for tens of seconds on a dead domain. Bound it to 3 seconds; on timeout the caller
   * falls through to the DoH fallback, which is itself socket-timeout bounded.
   */
  private fun resolveHostWithTimeout(host: String, timeoutMs: Long = 3000L): Array<InetAddress>? {
    val future = dnsExecutor.submit<Array<InetAddress>> { InetAddress.getAllByName(host) }
    return try {
      future.get(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (_: Exception) {
      future.cancel(true)
      null
    }
  }

  fun resolveEndpointIpv4(host: String): String? {
    val trimmed = host.trim()
    if (trimmed.isEmpty()) return null
    parseIpv4Bytes(trimmed)?.let { bytes ->
      return if (isPublicRoutableIpv4(bytes)) trimmed else null
    }
    resolvedEndpointCache[trimmed.lowercase()]?.let { return it }
    LocalV2RayProxyServer.lookupRealIpForDomain(trimmed)?.let { tunnelResolvedIp ->
      resolvedEndpointCache[trimmed.lowercase()] = tunnelResolvedIp
      return tunnelResolvedIp
    }

    try {
      val candidates = resolveHostWithTimeout(trimmed).orEmpty()
      for (addr in candidates) {
        if (addr is Inet4Address) {
          val bytes = addr.address
          if (bytes != null && bytes.size == 4 && isPublicRoutableIpv4(bytes)) {
            val ip = addr.hostAddress ?: continue
            resolvedEndpointCache[trimmed.lowercase()] = ip
            return ip
          }
        }
      }
    } catch (_: Exception) {}

    // Fallback: Resolve via encrypted DNS-over-HTTPS (1.1.1.1 / 8.8.8.8) if system DNS failed or was poisoned
    resolveViaDirectDoh(trimmed)?.let { cleanIp ->
      resolvedEndpointCache[trimmed.lowercase()] = cleanIp
      return cleanIp
    }

    return null
  }

  fun parseIpv4Bytes(host: String): ByteArray? {
    val parts = host.split(".")
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    for (i in 0..3) {
      val n = parts[i].toIntOrNull() ?: return null
      if (n !in 0..255) return null
      bytes[i] = n.toByte()
    }
    return bytes
  }

  fun parseIpv6Bytes(host: String): ByteArray? {
    val clean = host.removePrefix("[").removeSuffix("]").trim()
    if (!clean.contains(":")) return null
    return try {
      val addr = InetAddress.getByName(clean)
      if (addr is Inet6Address) addr.address else null
    } catch (_: Exception) {
      null
    }
  }

  fun isPublicRoutableIpv4(bytes: ByteArray): Boolean {
    if (bytes.size != 4) return false
    val b0 = bytes[0].toInt() and 0xFF
    val b1 = bytes[1].toInt() and 0xFF
    if (b0 == 0 || b0 == 10 || b0 == 127) return false
    if (b0 == 172 && b1 in 16..31) return false
    if (b0 == 192 && b1 == 168) return false
    if (b0 == 100 && b1 in 64..127) return false
    if (b0 >= 224) return false
    return true
  }

  private fun resolveViaDirectDoh(domain: String): String? {
    val query = buildDnsAQuery(domain)
    for (dohIp in listOf(byteArrayOf(1, 1, 1, 1), byteArrayOf(8, 8, 8, 8))) {
      try {
        Socket().use { raw ->
          raw.tcpNoDelay = true
          raw.soTimeout = 2500
          raw.connect(InetSocketAddress(InetAddress.getByAddress(dohIp), 443), 2500)
          val hostStr =
            if ((dohIp[0].toInt() and 0xFF) == 1) "cloudflare-dns.com" else "dns.google"
          val fragOut =
            GfwKnockerXrayCore.FragmentWriterOutputStream(
              raw.getOutputStream(),
              GfwKnockerXrayCore.FragmentConfig.AETHER_SNI_SPLIT,
            )
          val (tlsIn, tlsOut) =
            GfwKnockerXrayCore.openSslEngineOverStreams(
              sslContext = createSmartSslContext(hostStr, allowInsecureFallback = true),
              rawIn = raw.getInputStream(),
              rawOut = fragOut,
              sniHost = hostStr,
              port = 443,
            )
          val req =
            "POST /dns-query HTTP/1.1\r\n" +
              "Host: $hostStr\r\n" +
              "Content-Type: application/dns-message\r\n" +
              "Accept: application/dns-message\r\n" +
              "Content-Length: ${query.size}\r\n" +
              "Connection: close\r\n\r\n"
          tlsOut.write(req.toByteArray(Charsets.US_ASCII))
          tlsOut.write(query)
          tlsOut.flush()
          val respBytes = readHttpBody(tlsIn, 2048) ?: return@use
          extractFirstPublicARecord(respBytes)?.let { return it }
        }
      } catch (_: Exception) {}
    }
    return null
  }

  /**
   * Stage 1 Fast Probe: Opens a V2Ray tunnel to `connectivitycheck.gstatic.com:80`
   * and verifies `HTTP/1.1 204`.
   */
  fun measureRealProxyDelay(
    config: V2RayConfig,
    timeoutMs: Int = 2400,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    if (!isSupportedByEngine(config)) return null
    if (config.protocol == V2RayProtocol.SERVERLESS) {
      return verifyHttpsAndDnsCapability(config, timeoutMs = timeoutMs, protector = protector)
    }
    val resolvedIp = config.resolvedIp.ifBlank { resolveEndpointIpv4(config.address).orEmpty() }
    if (resolvedIp.isEmpty()) return null
    val resolvedConfig = config.copy(resolvedIp = resolvedIp)

    return try {
      var latencyMs = -1L
      val elapsedNanos =
        measureNanoTime {
          openTunnel(
            config = resolvedConfig,
            targetHost = "connectivitycheck.gstatic.com",
            targetPort = 80,
            timeoutMs = timeoutMs,
            protector = protector,
            usePrewarmedPool = false,
          ).use { conn ->
            val probeRequest =
              "GET /generate_204 HTTP/1.1\r\n" +
                "Host: connectivitycheck.gstatic.com\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Connection: close\r\n\r\n"
            conn.outputStream.write(probeRequest.toByteArray(Charsets.US_ASCII))
            conn.outputStream.flush()

            val responseBuf = ByteArrayOutputStream(256)
            val chunk = ByteArray(256)
            while (responseBuf.size() < 220) {
              val n = conn.inputStream.read(chunk)
              if (n <= 0) break
              responseBuf.write(chunk, 0, n)
              val textSoFar = responseBuf.toString("US-ASCII")
              if (textSoFar.contains("\r\n\r\n")) {
                break
              }
            }
            val responseText = responseBuf.toString("US-ASCII")
            if (!responseText.startsWith("HTTP/1.1 204")) {
              throw IOException("Invalid gstatic 204 probe response: ${responseText.take(48)}")
            }
          }
        }
      latencyMs = (elapsedNanos / 1_000_000L).coerceAtLeast(1L)
      latencyMs
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Stage 2 Strict Verification: Opens a SECOND independent V2Ray tunnel to `www.google.com:443`,
   * performs a real end-to-end TLS handshake with `www.google.com` INSIDE the V2Ray tunnel using
   * `SSLEngine` with strict-first certificate validation, and verifies `GET /generate_204 -> HTTP/1.1 204`.
   */
  fun verifyHttpsAndDnsCapability(
    config: V2RayConfig,
    timeoutMs: Int = 2800,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    if (!isSupportedByEngine(config)) return null
    val resolvedIp = config.resolvedIp.ifBlank { resolveEndpointIpv4(config.address).orEmpty() }
    if (resolvedIp.isEmpty()) return null
    val resolvedConfig = config.copy(resolvedIp = resolvedIp)

    return try {
      val elapsedNanos =
        measureNanoTime {
          openTunnel(
            config = resolvedConfig,
            targetHost = "www.google.com",
            targetPort = 443,
            timeoutMs = timeoutMs,
            protector = protector,
            usePrewarmedPool = false,
          ).use { tunnel ->
            val (tlsIn, tlsOut) =
              GfwKnockerXrayCore.openSslEngineOverStreams(
                sslContext = createSmartSslContext("www.google.com", allowInsecureFallback = true),
                rawIn = tunnel.inputStream,
                rawOut = tunnel.outputStream,
                sniHost = "www.google.com",
                port = 443,
              )
            val req =
              "GET /generate_204 HTTP/1.1\r\n" +
                "Host: www.google.com\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Connection: close\r\n\r\n"
            tlsOut.write(req.toByteArray(Charsets.US_ASCII))
            tlsOut.flush()

            val buf = ByteArray(128)
            val n = tlsIn.read(buf)
            if (n <= 0) throw IOException("Empty HTTPS 443 response over tunnel")
            val statusLine = String(buf, 0, n, Charsets.US_ASCII)
            if (!statusLine.startsWith("HTTP/1.1 204") && !statusLine.startsWith("HTTP/2 204")) {
              throw IOException("Unexpected HTTPS 443 status: ${statusLine.take(32)}")
            }
          }
        }
      (elapsedNanos / 1_000_000L).coerceAtLeast(1L)
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Measures actual download throughput (in KB/s) over the V2Ray tunnel by downloading up to
   * [targetBytes] from `www.google.com:443`. Only the body transfer (first byte to last byte, capped
   * at ~1.5 s) is timed, so node scoring reflects bandwidth rather than handshake latency.
   */
  fun measureSmallDownloadThroughputKbps(
    config: V2RayConfig,
    timeoutMs: Int = 2600,
    targetBytes: Int = 16_384,
    protector: ((Socket) -> Boolean)? = null,
  ): Double? {
    if (!isSupportedByEngine(config)) return null
    val resolvedIp = config.resolvedIp.ifBlank { resolveEndpointIpv4(config.address).orEmpty() }
    if (resolvedIp.isEmpty()) return null
    val resolvedConfig = config.copy(resolvedIp = resolvedIp)

    return try {
      var totalBytesRead = 0
      var bodyBytes = 0
      var bodyNs = 0L
      val startNs = System.nanoTime()
      openTunnel(
        config = resolvedConfig,
        targetHost = "www.google.com",
        targetPort = 443,
        timeoutMs = timeoutMs,
        protector = protector,
        usePrewarmedPool = false,
      ).use { tunnel ->
        val (tlsIn, tlsOut) =
          GfwKnockerXrayCore.openSslEngineOverStreams(
            sslContext = createSmartSslContext("www.google.com", allowInsecureFallback = true),
            rawIn = tunnel.inputStream,
            rawOut = tunnel.outputStream,
            sniHost = "www.google.com",
            port = 443,
          )
        val req =
          "GET / HTTP/1.1\r\n" +
            "Host: www.google.com\r\n" +
            "User-Agent: Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36\r\n" +
            "Accept-Encoding: identity\r\n" +
            "Connection: close\r\n\r\n"
        tlsOut.write(req.toByteArray(Charsets.US_ASCII))
        tlsOut.flush()

        // Time only the body transfer (first byte -> last byte): connect + TLS handshake + request
        // latency would otherwise dominate a small download and make this a second ping test.
        val buf = ByteArray(8192)
        var firstByteNs = 0L
        var lastByteNs = 0L
        var bytesAfterFirst = 0
        try {
          while (totalBytesRead < targetBytes) {
            val n = tlsIn.read(buf)
            if (n <= 0) break
            val now = System.nanoTime()
            if (firstByteNs == 0L) {
              firstByteNs = now
              tunnel.setReadTimeout(1200)
            } else {
              bytesAfterFirst += n
            }
            lastByteNs = now
            totalBytesRead += n
            if (now - firstByteNs > 1_500_000_000L) break
          }
        } catch (_: Exception) {
          // Keep whatever arrived before the stall/timeout; it still says something about speed.
        }
        bodyBytes = bytesAfterFirst
        bodyNs = lastByteNs - firstByteNs
      }
      if (totalBytesRead < 512) return null
      if (bodyBytes >= 8192 && bodyNs > 0L) {
        return (bodyBytes / 1024.0) / (bodyNs / 1_000_000_000.0)
      }
      val elapsedSec = ((System.nanoTime() - startNs) / 1_000_000_000.0).coerceAtLeast(0.02)
      (totalBytesRead / 1024.0) / elapsedSec
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Verifies direct connection capability to Telegram Data Centers (e.g. 149.154.167.50:443).
   */
  fun verifyTelegramCapability(
    config: V2RayConfig,
    timeoutMs: Int = 2400,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    if (!isSupportedByEngine(config)) return null
    val resolvedIp = config.resolvedIp.ifBlank { resolveEndpointIpv4(config.address).orEmpty() }
    if (resolvedIp.isEmpty()) return null
    val resolvedConfig = config.copy(resolvedIp = resolvedIp)

    return try {
      val elapsedNanos =
        measureNanoTime {
          openTunnel(
            config = resolvedConfig,
            targetHost = "149.154.167.50",
            targetPort = 443,
            timeoutMs = timeoutMs,
            protector = protector,
            usePrewarmedPool = false,
          ).use { conn ->
            conn.outputStream.write(
              byteArrayOf(0xef.toByte(), 0xef.toByte(), 0xef.toByte(), 0xef.toByte())
            )
            conn.outputStream.flush()
          }
        }
      (elapsedNanos / 1_000_000L).coerceAtLeast(1L)
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Verifies that this V2Ray server can establish a real end-to-end TLS 443 session to Twitter/X
   * (`api.x.com:443`) and receive an HTTP response.
   */
  fun verifySocialMediaCapability(
    config: V2RayConfig,
    timeoutMs: Int = 2600,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    return verifyTlsTargetHostCapability(
      config = config,
      targetHost = "api.x.com",
      requestPath = "/1.1/help/settings.json",
      timeoutMs = timeoutMs,
      protector = protector,
    )
  }

  /**
   * Verifies that this V2Ray server can establish a real end-to-end TLS 443 session to Instagram's
   * mobile API (`i.instagram.com:443`) and receive an HTTP response.
   */
  fun verifyInstagramCapability(
    config: V2RayConfig,
    timeoutMs: Int = 2600,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    return verifyTlsTargetHostCapability(
      config = config,
      targetHost = "i.instagram.com",
      requestPath = "/api/v1/si/fetch_headers/",
      timeoutMs = timeoutMs,
      protector = protector,
    )
  }

  private fun verifyTlsTargetHostCapability(
    config: V2RayConfig,
    targetHost: String,
    requestPath: String,
    timeoutMs: Int = 2600,
    protector: ((Socket) -> Boolean)? = null,
  ): Long? {
    if (!isSupportedByEngine(config)) return null
    val resolvedIp = config.resolvedIp.ifBlank { resolveEndpointIpv4(config.address).orEmpty() }
    if (resolvedIp.isEmpty()) return null
    val resolvedConfig = config.copy(resolvedIp = resolvedIp)

    return try {
      val elapsedNanos =
        measureNanoTime {
          openTunnel(
            config = resolvedConfig,
            targetHost = targetHost,
            targetPort = 443,
            timeoutMs = timeoutMs,
            protector = protector,
            usePrewarmedPool = false,
          ).use { tunnel ->
            val (tlsIn, tlsOut) =
              GfwKnockerXrayCore.openSslEngineOverStreams(
                sslContext = createSmartSslContext(targetHost, allowInsecureFallback = true),
                rawIn = tunnel.inputStream,
                rawOut = tunnel.outputStream,
                sniHost = targetHost,
                port = 443,
              )
            val req =
              "GET $requestPath HTTP/1.1\r\n" +
                "Host: $targetHost\r\n" +
                "User-Agent: Mozilla/5.0 (Linux; Android 9; SM-G950F) AppleWebKit/537.36\r\n" +
                "Connection: close\r\n\r\n"
            tlsOut.write(req.toByteArray(Charsets.US_ASCII))
            tlsOut.flush()

            val buf = ByteArray(128)
            val n = tlsIn.read(buf)
            if (n <= 0) throw IOException("Empty response from $targetHost over tunnel")
            val statusLine = String(buf, 0, n, Charsets.US_ASCII)
            if (!statusLine.startsWith("HTTP/1.1 ") && !statusLine.startsWith("HTTP/2")) {
              throw IOException("Unexpected $targetHost status: ${statusLine.take(24)}")
            }
          }
        }
      (elapsedNanos / 1_000_000L).coerceAtLeast(1L)
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Dials the underlying TCP + TLS + WebSocket/HTTPUpgrade transport to [config] WITHOUT sending
   * the VLESS/Trojan header yet. This allows pre-warming a pool of ready connections per node.
   */
  private fun dialNodeTransport(
    config: V2RayConfig,
    timeoutMs: Int,
    protector: ((Socket) -> Boolean)?,
  ): PrewarmedNodeTransport {
    val net = config.network.lowercase().trim()
    if (net == "kcp" || net == "mkcp") {
      val (kcpIn, kcpOut) = AdvancedTransportsEngine.openMkcpTransport(config, timeoutMs, protector)
      return PrewarmedNodeTransport(
        rawSocket = Socket(),
        tlsSocket = null,
        transportIn = kcpIn,
        transportOut = kcpOut,
      )
    }

    val rawSocket = Socket()
    try {
      try {
        rawSocket.reuseAddress
      } catch (_: Exception) {}
      protector?.invoke(rawSocket)
      rawSocket.tcpNoDelay = true
      rawSocket.keepAlive = true
      rawSocket.soTimeout = timeoutMs

      val connectHost =
        config.resolvedIp.ifBlank {
          resolveEndpointIpv4(config.address) ?: config.address
        }
      val ipv4Bytes = parseIpv4Bytes(connectHost)
      val remoteEndpoint =
        if (ipv4Bytes != null) {
          InetSocketAddress(InetAddress.getByAddress(ipv4Bytes), config.port)
        } else {
          InetSocketAddress(connectHost, config.port)
        }
      rawSocket.connect(remoteEndpoint, timeoutMs)

      val sec = config.security.lowercase().trim()
      val isReality = sec == "reality" || config.pbk.isNotBlank()
      val isTls = sec == "tls"
      var activeSslSocket: SSLSocket? = null
      val (rawTransportIn, rawTransportOut) =
        when {
          isReality -> {
            val realityTriple =
              AdvancedTransportsEngine.establishRealityTlsStreams(rawSocket, config, timeoutMs)
            activeSslSocket = realityTriple.third
            Pair(realityTriple.first, realityTriple.second)
          }
          isTls -> {
            val tlsTriple = establishTlsStreams(rawSocket, config, timeoutMs)
            activeSslSocket = tlsTriple.third
            Pair(tlsTriple.first, tlsTriple.second)
          }
          else -> {
            val tcpProfile =
              if (config.fragmentProfile.startsWith("patterniha")) {
                GfwKnockerXrayCore.FragmentConfig.PATTERNIHA_TCP_DIRECT
              } else {
                GfwKnockerXrayCore.FragmentConfig.DEFAULT_TCP_PACKETS
              }
            Pair(
              BufferedInputStream(rawSocket.getInputStream(), 32768),
              GfwKnockerXrayCore.FragmentWriterOutputStream(
                rawSocket.getOutputStream(),
                tcpProfile,
              ),
            )
          }
        }

      var transportIn: InputStream = rawTransportIn
      var transportOut: OutputStream = rawTransportOut

      when (net) {
        "ws" -> {
          performWebSocketUpgrade(config, transportIn, transportOut)
          val wsOut = WebSocketFrameOutputStream(transportOut)
          val wsIn = WebSocketFrameInputStream(transportIn) { pongPayload ->
            wsOut.sendPong(pongPayload)
          }
          transportIn = wsIn
          transportOut = wsOut
        }
        "httpupgrade" -> {
          GfwKnockerXrayCore.performHttpUpgrade(config, transportIn, transportOut)
        }
        "grpc" -> {
          val (gIn, gOut) =
            AdvancedTransportsEngine.openGrpcOrH2Stream(config, transportIn, transportOut, isGrpc = true)
          transportIn = gIn
          transportOut = gOut
        }
        "h2", "http" -> {
          val (hIn, hOut) =
            AdvancedTransportsEngine.openGrpcOrH2Stream(config, transportIn, transportOut, isGrpc = false)
          transportIn = hIn
          transportOut = hOut
        }
        "xhttp", "splithttp" -> {
          val (xIn, xOut) =
            AdvancedTransportsEngine.openXhttpStream(config, transportIn, transportOut)
          transportIn = xIn
          transportOut = xOut
        }
        "tcp" -> {
          if (config.headerType.equals("http", ignoreCase = true)) {
            val (obfsIn, obfsOut) =
              AdvancedTransportsEngine.wrapTcpHttpObfuscation(config, transportIn, transportOut)
            transportIn = obfsIn
            transportOut = obfsOut
          }
        }
      }

      return PrewarmedNodeTransport(
        rawSocket = rawSocket,
        tlsSocket = activeSslSocket,
        transportIn = transportIn,
        transportOut = transportOut,
      )
    } catch (e: Exception) {
      try {
        rawSocket.close()
      } catch (_: Exception) {}
      throw e
    }
  }

  /**
   * Establishes an outbound V2Ray tunnel to [targetHost]:[targetPort] through [config].
   * When [usePrewarmedPool] is true, consumes a pre-warmed TLS+WS transport if available (0-RTT)
   * and schedules background replenishment.
   */
  fun openTunnel(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 7000,
    protector: ((Socket) -> Boolean)? = null,
    fallbackIpv4: String? = null,
    usePrewarmedPool: Boolean = true,
    vlessCommand: Int = VLESS_CMD_TCP,
  ): TunnelConnection {
    MehDiag.recordTcpConnectAttempt()
    if (config.protocol == V2RayProtocol.SERVERLESS) {
      return try {
        openDirectServerlessFragmentTunnel(
          config = config,
          targetHost = targetHost,
          targetPort = targetPort,
          timeoutMs = timeoutMs,
          protector = protector,
          fallbackIpv4 = fallbackIpv4,
        ).also { MehDiag.recordTcpConnectSuccess() }
      } catch (e: Exception) {
        MehDiag.recordTcpConnectFailure()
        throw e
      }
    }

    if (config.protocol == V2RayProtocol.WIREGUARD) {
      return try {
        NextGenProtocolsEngine.openWireGuardTunnel(
          config = config,
          targetHost = targetHost,
          targetPort = targetPort,
          timeoutMs = timeoutMs,
          protector = protector,
        ).also { MehDiag.recordTcpConnectSuccess() }
      } catch (e: Exception) {
        MehDiag.recordTcpConnectFailure()
        throw e
      }
    }

    val prewarmed =
      if (usePrewarmedPool && canUsePrewarmedPool(config)) {
        pollPrewarmedTransport(config)
      } else {
        null
      }

    val transport =
      if (prewarmed != null) {
        MehDiag.recordPrewarmedPoolHit()
        warmUpNodePoolAsync(config, protector)
        prewarmed
      } else {
        if (usePrewarmedPool && canUsePrewarmedPool(config)) {
          MehDiag.recordPrewarmedPoolMiss()
        }
        try {
          dialNodeTransport(config, timeoutMs, protector).also {
            if (usePrewarmedPool && canUsePrewarmedPool(config)) {
              warmUpNodePoolAsync(config, protector)
            }
          }
        } catch (e: Exception) {
          MehDiag.recordTcpConnectFailure()
          throw e
        }
      }

    try {
      try {
        transport.rawSocket.soTimeout = timeoutMs
      } catch (_: Exception) {}
      try {
        transport.tlsSocket?.soTimeout = timeoutMs
      } catch (_: Exception) {}

      val conn =
        when (config.protocol) {
          V2RayProtocol.VLESS,
          V2RayProtocol.MVLESS,
          V2RayProtocol.JVLESS ->
            setupVlessStream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
              command = vlessCommand,
            )
          V2RayProtocol.TROJAN ->
            setupTrojanStream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
              command = if (vlessCommand == VLESS_CMD_UDP) 0x03 else 0x01,
            )
          V2RayProtocol.VMESS ->
            VmessAndShadowsocksEngine.setupVmessStream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
              isUdp = (vlessCommand == VLESS_CMD_UDP),
            )
          V2RayProtocol.SHADOWSOCKS ->
            VmessAndShadowsocksEngine.setupShadowsocksStream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
            )
          V2RayProtocol.HYSTERIA2 ->
            NextGenProtocolsEngine.setupHysteria2Stream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
            )
          V2RayProtocol.TUIC ->
            NextGenProtocolsEngine.setupTuicV5Stream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
            )
          V2RayProtocol.SOCKS5 ->
            VmessAndShadowsocksEngine.setupSocks5Stream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
            )
          V2RayProtocol.HTTP_PROXY ->
            VmessAndShadowsocksEngine.setupHttpProxyStream(
              transport.rawSocket,
              transport.tlsSocket,
              transport.transportIn,
              transport.transportOut,
              config,
              targetHost,
              targetPort,
            )
          else -> throw IOException("Unsupported protocol: ${config.protocol}")
        }
      MehDiag.recordTcpConnectSuccess()
      return conn
    } catch (e: Exception) {
      transport.closeQuietly()
      MehDiag.recordTcpConnectFailure()
      throw e
    }
  }

  /**
   * Exchanges a UDP datagram over the active node using VLESS UDP (`0x02`), Trojan UDP (`0x03`),
   * VMess UDP (`0x02`), or Shadowsocks UDP.
   */
  fun exchangeVlessUdpDatagram(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    udpPayload: ByteArray,
    timeoutMs: Int = 3500,
    protector: ((Socket) -> Boolean)? = null,
  ): ByteArray? {
    if (udpPayload.isEmpty() || udpPayload.size > 65507) return null

    if (config.protocol == V2RayProtocol.TROJAN) {
      return NextGenProtocolsEngine.exchangeTrojanUdpDatagram(
        config = config,
        targetHost = targetHost,
        targetPort = targetPort,
        udpPayload = udpPayload,
        timeoutMs = timeoutMs,
        protector = protector,
      )
    }

    if (config.protocol == V2RayProtocol.SHADOWSOCKS) {
      return VmessAndShadowsocksEngine.exchangeShadowsocksUdpDatagram(
        config = config,
        targetHost = targetHost,
        targetPort = targetPort,
        udpPayload = udpPayload,
        timeoutMs = timeoutMs,
      )
    }

    val isVlessOrVmess =
      config.protocol == V2RayProtocol.VLESS ||
        config.protocol == V2RayProtocol.MVLESS ||
        config.protocol == V2RayProtocol.JVLESS ||
        config.protocol == V2RayProtocol.VMESS
    if (!isVlessOrVmess) return null

    return try {
      openTunnel(
        config = config,
        targetHost = targetHost,
        targetPort = targetPort,
        timeoutMs = timeoutMs,
        protector = protector,
        usePrewarmedPool = true,
        vlessCommand = VLESS_CMD_UDP,
      ).use { tunnel ->
        tunnel.setReadTimeout(timeoutMs)
        if (config.protocol == V2RayProtocol.VMESS) {
          tunnel.outputStream.write(udpPayload)
          tunnel.outputStream.flush()
          MehDiag.recordBytesUploaded(udpPayload.size.toLong())
          val recvBuf = ByteArray(65507)
          val n = tunnel.inputStream.read(recvBuf)
          if (n <= 0) return null
          MehDiag.recordBytesDownloaded(n.toLong())
          MehDiag.recordUdpVlessRelayedPacket()
          return recvBuf.copyOf(n)
        }

        val framedOut = ByteArray(2 + udpPayload.size)
        framedOut[0] = ((udpPayload.size ushr 8) and 0xFF).toByte()
        framedOut[1] = (udpPayload.size and 0xFF).toByte()
        System.arraycopy(udpPayload, 0, framedOut, 2, udpPayload.size)
        tunnel.outputStream.write(framedOut)
        tunnel.outputStream.flush()
        MehDiag.recordBytesUploaded(framedOut.size.toLong())

        val lenHeader = ByteArray(2)
        val dataIn = DataInputStream(tunnel.inputStream)
        dataIn.readFully(lenHeader)
        val respLen = ((lenHeader[0].toInt() and 0xFF) shl 8) or (lenHeader[1].toInt() and 0xFF)
        if (respLen !in 1..65507) return null
        val respPayload = ByteArray(respLen)
        dataIn.readFully(respPayload)
        MehDiag.recordBytesDownloaded(respLen.toLong())
        MehDiag.recordUdpVlessRelayedPacket()
        respPayload
      }
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Direct Serverless Fragmented Tunnel (`patterniha/Serverless-for-Iran`, `CluvexStudio/Aether`, `WhiteDNS`).
   */
  private fun openDirectServerlessFragmentTunnel(
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int,
    protector: ((Socket) -> Boolean)?,
    fallbackIpv4: String? = null,
  ): TunnelConnection {
    val rawSocket = Socket()
    try {
      try {
        rawSocket.reuseAddress
      } catch (_: Exception) {}
      protector?.invoke(rawSocket)
      rawSocket.tcpNoDelay = true
      rawSocket.keepAlive = true
      rawSocket.soTimeout = timeoutMs

      val resolvedTargetIp =
        when {
          parseIpv4Bytes(targetHost)?.let { isPublicRoutableIpv4(it) } == true -> targetHost
          !fallbackIpv4.isNullOrBlank() &&
            parseIpv4Bytes(fallbackIpv4)?.let { isPublicRoutableIpv4(it) } == true -> fallbackIpv4
          else ->
            LocalV2RayProxyServer.lookupRealIpForDomain(targetHost)
              ?: resolveViaDirectDoh(targetHost)
              ?: resolveEndpointIpv4(targetHost)
              ?: targetHost
        }
      val ipv4Bytes = parseIpv4Bytes(resolvedTargetIp)
      val endpoint =
        if (ipv4Bytes != null) {
          InetSocketAddress(InetAddress.getByAddress(ipv4Bytes), targetPort)
        } else {
          InetSocketAddress(resolvedTargetIp, targetPort)
        }
      rawSocket.connect(endpoint, timeoutMs)

      val fragConfig =
        if (targetPort == 443 || targetPort == 8443 || targetPort == 2053 || targetPort == 2083) {
          GfwKnockerXrayCore.FragmentConfig.fromProfileId(config.fragmentProfile)
        } else {
          GfwKnockerXrayCore.FragmentConfig.PATTERNIHA_TCP_DIRECT
        }

      val directIn = BufferedInputStream(rawSocket.getInputStream(), 32768)
      val directOut =
        GfwKnockerXrayCore.FragmentWriterOutputStream(
          rawSocket.getOutputStream(),
          fragConfig,
        )
      return TunnelConnection(rawSocket, directIn, directOut, null)
    } catch (e: Exception) {
      try {
        rawSocket.close()
      } catch (_: Exception) {}
      throw e
    }
  }

  /**
   * Establishes TLS over [rawSocket] using [createSmartSslContext] so valid SNI/certificates are
   * strictly verified first before falling back to permissive mode on self-signed community nodes.
   */
  private fun establishTlsStreams(
    rawSocket: Socket,
    config: V2RayConfig,
    timeoutMs: Int,
  ): Triple<InputStream, OutputStream, SSLSocket?> {
    val sniHost =
      config.sni
        .ifBlank { config.hostHeader }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')

    val net = config.network.lowercase().trim()
    val isWsOrUpgrade = net == "ws" || net == "httpupgrade" || net == "xhttp" || net == "splithttp"
    val isH2OrGrpc = net == "grpc" || net == "h2" || net == "http"
    val alpn =
      when {
        isH2OrGrpc -> arrayOf("h2")
        isWsOrUpgrade -> arrayOf("http/1.1")
        config.alpn.isNotBlank() ->
          config.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toTypedArray()
        else -> null
      }

    val desiredCiphers =
      if (config.cipherSuites.isNotBlank()) {
        config.cipherSuites.split(":").map { it.trim() }.filter { it.isNotEmpty() }
      } else if (config.fragmentProfile.startsWith("patterniha")) {
        GfwKnockerXrayCore.PATTERNIHA_CIPHER_SUITES
      } else {
        emptyList()
      }

    val smartSsl = createSmartSslContext(sniHost, allowInsecureFallback = true)

    // 1. Standard direct TLS mode: uses real connected rawSocket directly with Android Conscrypt SSLSocket
    if (config.fragmentProfile.equals("direct_tls", ignoreCase = true) ||
      config.fragmentProfile.isBlank()
    ) {
      val sslSocket =
        smartSsl.socketFactory.createSocket(
          rawSocket,
          sniHost,
          config.port,
          true,
        ) as SSLSocket
      sslSocket.soTimeout = timeoutMs
      try {
        val params = sslSocket.sslParameters
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N &&
          sniHost.isNotEmpty() &&
          !sniHost[0].isDigit()
        ) {
          params.serverNames = listOf(SNIHostName(sniHost))
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q && alpn != null) {
          params.applicationProtocols = alpn
        }
        sslSocket.sslParameters = params
      } catch (_: Exception) {}
      sslSocket.startHandshake()
      return Triple(
        BufferedInputStream(sslSocket.getInputStream(), 16384),
        sslSocket.getOutputStream(),
        sslSocket,
      )
    }

    // 2. Fragmented TLS mode (GFW-knocker, CluvexStudio/Aether, WhiteDNS, Patterniha):
    // Uses pure SSLEngine over FragmentWriterOutputStream so Android 9 Conscrypt never sees a fake Socket fd!
    val fragProfile = GfwKnockerXrayCore.FragmentConfig.fromProfileId(config.fragmentProfile)
    val fragmentedOut =
      GfwKnockerXrayCore.FragmentWriterOutputStream(
        rawSocket.getOutputStream(),
        fragProfile,
      )
    val (tlsIn, tlsOut) =
      GfwKnockerXrayCore.openSslEngineOverStreams(
        sslContext = smartSsl,
        rawIn = BufferedInputStream(rawSocket.getInputStream(), 16384),
        rawOut = fragmentedOut,
        sniHost = sniHost,
        port = config.port,
        cipherSuites = desiredCiphers,
        alpnProtocols = alpn,
      )
    return Triple(BufferedInputStream(tlsIn, 16384), tlsOut, null)
  }

  private fun performWebSocketUpgrade(
    config: V2RayConfig,
    input: InputStream,
    output: OutputStream,
  ) {
    val wsHost =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { config.address }
        .trim()
        .trimEnd('.')
    val rawPath = config.path.substringBefore("?ed=").ifBlank { "/" }
    val wsPath = if (rawPath.startsWith("/")) rawPath else "/$rawPath"

    val keyBytes = ByteArray(16).also { secureRandom.nextBytes(it) }
    val wsKey = encodeBase64NoWrap(keyBytes)

    val requestHeaders =
      "GET $wsPath HTTP/1.1\r\n" +
        "Host: $wsHost\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: $wsKey\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "User-Agent: ${GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT}\r\n\r\n"

    output.write(requestHeaders.toByteArray(Charsets.US_ASCII))
    output.flush()

    val headerBuf = ByteArrayOutputStream(512)
    var state = 0
    while (headerBuf.size() < 8192) {
      val b = input.read()
      if (b == -1) throw EOFException("EOF during WebSocket handshake")
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
    val responseText = headerBuf.toString("US-ASCII")
    val firstLine = responseText.lineSequence().firstOrNull().orEmpty()
    if (!firstLine.contains(" 101 ")) {
      throw IOException("WebSocket upgrade rejected: $firstLine")
    }
  }

  private fun setupVlessStream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    command: Int = VLESS_CMD_TCP,
  ): TunnelConnection {
    val uuidBytes =
      parseUuidBytes(config.authId) ?: throw IOException("Invalid VLESS UUID: ${config.authId}")

    val wireVersion = GfwKnockerXrayCore.vlessWireVersionFor(config.protocol).toInt() and 0xFF
    val flowAddon = AdvancedTransportsEngine.encodeVlessFlowAddon(config.flow)

    val header = ByteArrayOutputStream(64)
    header.write(wireVersion) // 0x00 (VLESS), 150/0x96 (MVLESS), or 0x78 (JVLESS)
    header.write(uuidBytes) // 16-byte UUID
    header.write(flowAddon.size and 0xFF) // Addons length (0 or 18 for xtls-rprx-vision)
    if (flowAddon.isNotEmpty()) {
      header.write(flowAddon)
    }
    header.write(command and 0xFF) // Command = 0x01 (TCP) or 0x02 (UDP)
    header.write((targetPort ushr 8) and 0xFF) // Port high byte
    header.write(targetPort and 0xFF) // Port low byte

    writeVlessAddress(header, targetHost)
    val headerBytes = header.toByteArray()
    val headerSentLatch = CountDownLatch(1)

    val vlessOut =
      object : FilterOutputStream(output) {
        private var headerSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (!headerSent) {
            headerSent = true
            try {
              val combined = ByteArray(headerBytes.size + len)
              System.arraycopy(headerBytes, 0, combined, 0, headerBytes.size)
              System.arraycopy(b, off, combined, headerBytes.size, len)
              out.write(combined)
              out.flush()
            } finally {
              headerSentLatch.countDown()
            }
          } else {
            out.write(b, off, len)
          }
        }
      }

    val vlessIn =
      object : FilterInputStream(input) {
        // Header parsing is resumable: a read timeout while waiting for the response must not
        // mark the header as consumed, otherwise the next read would hand the raw VLESS header
        // bytes (00 00) to the application as payload.
        private var headerDone = false
        private var versionChecked = false
        private var addonRemaining = -1

        @Synchronized
        private fun ensureHeader() {
          if (headerDone) return
          headerSentLatch.await(30_000, TimeUnit.MILLISECONDS)
          if (!versionChecked) {
            val ver = `in`.read()
            if (ver == -1) throw EOFException("VLESS EOF before response header")
            if (ver != wireVersion && ver != 0) {
              throw IOException("Invalid VLESS response version byte: $ver")
            }
            versionChecked = true
          }
          if (addonRemaining < 0) {
            val addonLen = `in`.read()
            if (addonLen == -1) throw EOFException("VLESS EOF reading addon length")
            addonRemaining = addonLen
          }
          while (addonRemaining > 0) {
            val b = `in`.read()
            if (b == -1) throw EOFException("VLESS EOF skipping addons")
            addonRemaining--
          }
          headerDone = true
        }

        override fun read(): Int {
          ensureHeader()
          return `in`.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
          ensureHeader()
          return `in`.read(b, off, len)
        }
      }

    if (config.flow.startsWith("xtls-rprx-vision", ignoreCase = true) && command == VLESS_CMD_TCP) {
      val (visionIn, visionOut) =
        AdvancedTransportsEngine.wrapXtlsVisionStream(uuidBytes, vlessIn, vlessOut)
      return TunnelConnection(socket, visionIn, visionOut, tlsSocket)
    }

    return TunnelConnection(socket, vlessIn, vlessOut, tlsSocket)
  }

  private fun setupTrojanStream(
    socket: Socket,
    tlsSocket: SSLSocket?,
    input: InputStream,
    output: OutputStream,
    config: V2RayConfig,
    targetHost: String,
    targetPort: Int,
    command: Int = 0x01,
  ): TunnelConnection {
    val passwordHashHex = sha224Hex(config.authId)
    val header = ByteArrayOutputStream(128)
    header.write(passwordHashHex.toByteArray(Charsets.US_ASCII))
    header.write(byteArrayOf(0x0D, 0x0A))
    header.write(command and 0xFF) // 0x01 = CONNECT (TCP), 0x03 = UDP ASSOCIATE (Trojan UDP)
    writeSocks5Address(header, targetHost)
    header.write((targetPort ushr 8) and 0xFF)
    header.write(targetPort and 0xFF)
    header.write(byteArrayOf(0x0D, 0x0A))
    val headerBytes = header.toByteArray()

    val trojanOut =
      object : FilterOutputStream(output) {
        private var headerSent = false

        @Synchronized
        override fun write(b: Int) {
          write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
          if (!headerSent) {
            headerSent = true
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

    return TunnelConnection(socket, input, trojanOut, tlsSocket)
  }

  private fun writeVlessAddress(out: ByteArrayOutputStream, host: String) {
    val ipv4Bytes = parseIpv4Bytes(host)
    if (ipv4Bytes != null) {
      out.write(0x01) // IPv4
      out.write(ipv4Bytes)
      return
    }
    val ipv6Bytes = parseIpv6Bytes(host)
    if (ipv6Bytes != null && ipv6Bytes.size == 16) {
      out.write(0x03) // IPv6 (16 bytes) in VLESS
      out.write(ipv6Bytes)
      return
    }
    val domainBytes = host.toByteArray(Charsets.UTF_8)
    out.write(0x02) // Domain
    out.write(domainBytes.size)
    out.write(domainBytes)
  }

  private fun writeSocks5Address(out: ByteArrayOutputStream, host: String) {
    val ipv4Bytes = parseIpv4Bytes(host)
    if (ipv4Bytes != null) {
      out.write(0x01) // IPv4
      out.write(ipv4Bytes)
      return
    }
    val ipv6Bytes = parseIpv6Bytes(host)
    if (ipv6Bytes != null && ipv6Bytes.size == 16) {
      out.write(0x04) // IPv6 (16 bytes) in SOCKS5/Trojan
      out.write(ipv6Bytes)
      return
    }
    val domainBytes = host.toByteArray(Charsets.UTF_8)
    out.write(0x03) // Domain in SOCKS5/Trojan
    out.write(domainBytes.size)
    out.write(domainBytes)
  }

  internal fun parseUuidBytesInternal(uuidStr: String): ByteArray? = parseUuidBytes(uuidStr)

  private fun parseUuidBytes(uuidStr: String): ByteArray? {
    val hex = uuidStr.trim().replace("-", "")
    if (hex.length != 32) return null
    val bytes = ByteArray(16)
    return try {
      for (i in 0 until 16) {
        val index = i * 2
        bytes[i] = hex.substring(index, index + 2).toInt(16).toByte()
      }
      bytes
    } catch (_: Exception) {
      null
    }
  }

  private fun sha224Hex(input: String): String {
    val md = MessageDigest.getInstance("SHA-224")
    val digest = md.digest(input.toByteArray(Charsets.UTF_8))
    val sb = StringBuilder(56)
    for (b in digest) {
      sb.append(String.format("%02x", b))
    }
    return sb.toString()
  }

  private const val BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  private fun encodeBase64NoWrap(data: ByteArray): String {
    val out = StringBuilder(((data.size + 2) / 3) * 4)
    var i = 0
    while (i < data.size) {
      val b0 = data[i].toInt() and 0xFF
      val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else 0
      val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xFF else 0
      val triple = (b0 shl 16) or (b1 shl 8) or b2
      out.append(BASE64_ALPHABET[(triple ushr 18) and 0x3F])
      out.append(BASE64_ALPHABET[(triple ushr 12) and 0x3F])
      out.append(if (i + 1 < data.size) BASE64_ALPHABET[(triple ushr 6) and 0x3F] else '=')
      out.append(if (i + 2 < data.size) BASE64_ALPHABET[triple and 0x3F] else '=')
      i += 3
    }
    return out.toString()
  }

  private fun buildDnsAQuery(domain: String): ByteArray {
    val out = ByteArrayOutputStream(64)
    out.write(byteArrayOf(0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
    for (label in domain.trimEnd('.').split(".")) {
      val bytes = label.toByteArray(Charsets.US_ASCII)
      out.write(bytes.size)
      out.write(bytes)
    }
    out.write(0x00)
    out.write(byteArrayOf(0x00, 0x01, 0x00, 0x01)) // QTYPE=A, QCLASS=IN
    return out.toByteArray()
  }

  internal fun readHttpBody(input: InputStream, maxBytes: Int): ByteArray? {
    val headerBuf = ByteArrayOutputStream(256)
    var state = 0
    while (headerBuf.size() < 4096) {
      val b = input.read()
      if (b == -1) return null
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
    val headers = headerBuf.toString("US-ASCII")
    if (!headers.startsWith("HTTP/1.1 200") && !headers.startsWith("HTTP/1.0 200")) return null
    val contentLen =
      headers
        .lineSequence()
        .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
        ?.substringAfter(":")
        ?.trim()
        ?.toIntOrNull()
        ?: -1

    if (contentLen in 12..maxBytes) {
      val body = ByteArray(contentLen)
      DataInputStream(input).readFully(body)
      return body
    }
    val rest = ByteArrayOutputStream(256)
    val buf = ByteArray(256)
    while (rest.size() < maxBytes) {
      val n = input.read(buf)
      if (n <= 0) break
      rest.write(buf, 0, n)
    }
    return if (rest.size() >= 12) rest.toByteArray() else null
  }

  private fun extractFirstPublicARecord(dnsPacket: ByteArray): String? {
    if (dnsPacket.size < 12) return null
    val qdCount = ((dnsPacket[4].toInt() and 0xFF) shl 8) or (dnsPacket[5].toInt() and 0xFF)
    val anCount = ((dnsPacket[6].toInt() and 0xFF) shl 8) or (dnsPacket[7].toInt() and 0xFF)
    if (anCount <= 0) return null
    var offset = 12
    repeat(qdCount) {
      offset = skipDnsName(dnsPacket, offset)
      if (offset < 0 || offset + 4 > dnsPacket.size) return null
      offset += 4
    }
    repeat(anCount) {
      offset = skipDnsName(dnsPacket, offset)
      if (offset < 0 || offset + 10 > dnsPacket.size) return null
      val type = ((dnsPacket[offset].toInt() and 0xFF) shl 8) or (dnsPacket[offset + 1].toInt() and 0xFF)
      val rdLen = ((dnsPacket[offset + 8].toInt() and 0xFF) shl 8) or (dnsPacket[offset + 9].toInt() and 0xFF)
      offset += 10
      if (offset + rdLen > dnsPacket.size) return null
      if (type == 1 && rdLen == 4) {
        val ipBytes = dnsPacket.copyOfRange(offset, offset + 4)
        if (isPublicRoutableIpv4(ipBytes)) {
          return "${ipBytes[0].toInt() and 0xFF}.${ipBytes[1].toInt() and 0xFF}.${ipBytes[2].toInt() and 0xFF}.${ipBytes[3].toInt() and 0xFF}"
        }
      }
      offset += rdLen
    }
    return null
  }

  internal fun skipDnsName(pkt: ByteArray, startOffset: Int): Int {
    var pos = startOffset
    while (pos < pkt.size) {
      val len = pkt[pos].toInt() and 0xFF
      if (len == 0) return pos + 1
      if ((len and 0xC0) == 0xC0) return pos + 2
      pos += 1 + len
    }
    return -1
  }

  /**
   * RFC 6455 WebSocket Binary Frame OutputStream (client-to-server frames must be masked).
   */
  private class WebSocketFrameOutputStream(out: OutputStream) : FilterOutputStream(out) {
    private val rng = SecureRandom()

    @Synchronized
    fun sendPong(payload: ByteArray) {
      try {
        val maskKey = ByteArray(4).also { rng.nextBytes(it) }
        val frame = ByteArrayOutputStream(payload.size + 14)
        frame.write(0x8A) // FIN + Pong opcode (0x0A)
        frame.write(0x80 or (payload.size and 0x7F))
        frame.write(maskKey)
        val masked = ByteArray(payload.size)
        for (i in payload.indices) {
          masked[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
        }
        frame.write(masked)
        out.write(frame.toByteArray())
        out.flush()
      } catch (_: Exception) {}
    }

    @Synchronized
    override fun write(b: Int) {
      write(byteArrayOf(b.toByte()), 0, 1)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
      if (len <= 0) return
      var cursor = off
      var remaining = len
      while (remaining > 0) {
        val chunkLen = minOf(remaining, 16384)
        writeSingleFrame(b, cursor, chunkLen)
        cursor += chunkLen
        remaining -= chunkLen
      }
    }

    private fun writeSingleFrame(b: ByteArray, off: Int, len: Int) {
      val maskKey = ByteArray(4).also { rng.nextBytes(it) }
      val frame = ByteArrayOutputStream(len + 14)
      frame.write(0x82) // FIN + Binary frame (0x02)
      when {
        len <= 125 -> frame.write(0x80 or len)
        len <= 65535 -> {
          frame.write(0x80 or 126)
          frame.write((len ushr 8) and 0xFF)
          frame.write(len and 0xFF)
        }
        else -> {
          frame.write(0x80 or 127)
          val longLen = len.toLong()
          for (shift in 56 downTo 0 step 8) {
            frame.write(((longLen ushr shift) and 0xFF).toInt())
          }
        }
      }
      frame.write(maskKey)
      val maskedPayload = ByteArray(len)
      for (i in 0 until len) {
        maskedPayload[i] = (b[off + i].toInt() xor maskKey[i and 3].toInt()).toByte()
      }
      frame.write(maskedPayload)
      out.write(frame.toByteArray())
    }
  }

  /**
   * RFC 6455 WebSocket Frame InputStream.
   */
  private class WebSocketFrameInputStream(
    input: InputStream,
    private val pongSender: ((ByteArray) -> Unit)? = null,
  ) : FilterInputStream(input) {
    private val dataIn = DataInputStream(input)
    private var currentPayload: ByteArray = ByteArray(0)
    private var currentOffset = 0

    @Synchronized
    override fun read(): Int {
      val single = ByteArray(1)
      val n = read(single, 0, 1)
      return if (n == -1) -1 else (single[0].toInt() and 0xFF)
    }

    @Synchronized
    override fun read(b: ByteArray, off: Int, len: Int): Int {
      if (len == 0) return 0
      while (currentOffset >= currentPayload.size) {
        if (!readNextFrame()) return -1
      }
      val available = currentPayload.size - currentOffset
      val toCopy = minOf(len, available)
      System.arraycopy(currentPayload, currentOffset, b, off, toCopy)
      currentOffset += toCopy
      return toCopy
    }

    @Synchronized
    override fun skip(n: Long): Long {
      if (n <= 0) return 0
      val buf = ByteArray(minOf(n, 4096L).toInt())
      val r = read(buf, 0, buf.size)
      return if (r <= 0) 0L else r.toLong()
    }

    private fun readNextFrame(): Boolean {
      while (true) {
        val b0 = `in`.read()
        if (b0 == -1) return false
        val opcode = b0 and 0x0F
        val b1 = `in`.read()
        if (b1 == -1) return false
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()

        if (payloadLen == 126L) {
          payloadLen = dataIn.readUnsignedShort().toLong()
        } else if (payloadLen == 127L) {
          payloadLen = dataIn.readLong()
        }

        val maskKey =
          if (masked) {
            ByteArray(4).also { dataIn.readFully(it) }
          } else {
            null
          }

        if (payloadLen > 4 * 1024 * 1024) {
          throw IOException("WebSocket frame too large: $payloadLen")
        }

        val payload = ByteArray(payloadLen.toInt())
        dataIn.readFully(payload)
        if (maskKey != null) {
          for (i in payload.indices) {
            payload[i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
          }
        }

        when (opcode) {
          0x08 -> return false
          0x09 -> {
            pongSender?.invoke(payload)
            continue
          }
          0x0A -> continue
          0x00, 0x01, 0x02 -> {
            if (payload.isNotEmpty()) {
              currentPayload = payload
              currentOffset = 0
              return true
            }
          }
        }
      }
    }
  }
}
