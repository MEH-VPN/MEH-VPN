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
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.RejectedExecutionHandler
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock

/**
 * Local multi-protocol proxy server supporting:
 * 1. Bounded `ThreadPoolExecutor` (`relayExecutor`) with graceful backpressure.
 * 2. Pre-warmed TLS+WebSocket V2Ray node connection pooling (`V2RayOutboundClient.warmUpNodePoolAsync`).
 * 3. Mid-stream Dead Server Detection & Automatic Failover:
 *    - If a stream sends a `ClientHello` / HTTP request and receives 0 bytes within
 *      `FIRST_BYTE_STALL_TIMEOUT_MS`, penalizes the stalled node and transparently fails over to
 *      the next verified node in `serverPool`.
 *    - Exposes `switchToNextHealthyNode()` for keep-alive probe failover.
 * 4. Iranian Direct Split-Tunneling (`IranRoutingRules`):
 *    - Resolves `.ir` and domestic domains directly to real Iranian IPv4s and routes Iranian
 *      banking/domestic TCP & UDP traffic directly via `VpnService.protect()`ed sockets.
 * 5. VLESS UDP (`Command = 0x02`) relay for non-QUIC UDP traffic (voice calls, STUN/WebRTC, NTP).
 * 6. Full `MehDiag` diagnostic & performance instrumentation.
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
    /**
     * Stream read timeout once downstream data has begun flowing. Must stay long: push channels,
     * messenger sockets and websockets without pings legitimately sit idle for minutes.
     */
    private const val IDLE_STREAM_TIMEOUT_MS = 300_000

    /** Shorter stream timeout when waiting on a stream that has not yet transferred bulk data. */
    private const val NO_DATA_STREAM_TIMEOUT_MS = 20_000

    /** Max wait for the very first response byte after sending TLS ClientHello / HTTP request. */
    private const val FIRST_BYTE_STALL_TIMEOUT_MS = 5500

    /** Wait applied to the retry on a second node after the first one stalled. */
    private const val FIRST_BYTE_RETRY_TIMEOUT_MS = 4000

    /**
     * How many different nodes one stalled stream may be tried on. A silent stream is ambiguous
     * (dead node *or* dead/slow destination), so more than two attempts only burns time.
     */
    private const val MAX_STALL_FAILOVER_NODES = 2

    private const val RELAY_BUFFER_SIZE = 32768
    private const val CONSECUTIVE_FAILURES_TO_PENALIZE = 2
    private const val MAX_RELAY_THREADS = 320

    /** Hard wall-clock budget for one whole DNS lookup. */
    private const val DNS_BUDGET_MS = 2500L
    private const val DNS_SLOT_TIMEOUT_MS = 1500
    private const val DNS_DOH_TIMEOUT_MS = 1500

    private const val MAX_MAPPING_ENTRIES = 4096

    private val realIpToDomain = ConcurrentHashMap<String, String>()
    private val domainToRealIp = ConcurrentHashMap<String, String>()

    /**
     * Passively records real IPv4 `A` records from an authentic DNS response.
     */
    fun recordRealDnsARecords(domain: String, dnsBytes: ByteArray) {
      val cleanDomain = domain.trim().trimEnd('.').lowercase()
      if (cleanDomain.isEmpty() || dnsBytes.size < 12) return
      if (realIpToDomain.size >= MAX_MAPPING_ENTRIES) {
        realIpToDomain.clear()
        domainToRealIp.clear()
      }
      val qdCount = ((dnsBytes[4].toInt() and 0xFF) shl 8) or (dnsBytes[5].toInt() and 0xFF)
      val anCount = ((dnsBytes[6].toInt() and 0xFF) shl 8) or (dnsBytes[7].toInt() and 0xFF)
      if (anCount <= 0) return

      var offset = 12
      repeat(qdCount) {
        offset = skipDnsNameStatic(dnsBytes, offset)
        if (offset < 0 || offset + 4 > dnsBytes.size) return
        offset += 4
      }
      var recordedFirstIpForDomain = false
      repeat(anCount) {
        offset = skipDnsNameStatic(dnsBytes, offset)
        if (offset < 0 || offset + 10 > dnsBytes.size) return
        val type = ((dnsBytes[offset].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 1].toInt() and 0xFF)
        val rdLen = ((dnsBytes[offset + 8].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 9].toInt() and 0xFF)
        offset += 10
        if (offset + rdLen > dnsBytes.size) return
        if (type == 1 && rdLen == 4) {
          val ipv4Bytes = dnsBytes.copyOfRange(offset, offset + 4)
          if (V2RayOutboundClient.isPublicRoutableIpv4(ipv4Bytes)) {
            val ipStr =
              "${ipv4Bytes[0].toInt() and 0xFF}.${ipv4Bytes[1].toInt() and 0xFF}.${ipv4Bytes[2].toInt() and 0xFF}.${ipv4Bytes[3].toInt() and 0xFF}"
            realIpToDomain[ipStr] = cleanDomain
            if (!recordedFirstIpForDomain) {
              domainToRealIp[cleanDomain] = ipStr
              recordedFirstIpForDomain = true
            }
          }
        }
        offset += rdLen
      }
    }

    fun lookupDomainForRealIp(hostOrIp: String): String? {
      return realIpToDomain[hostOrIp.trim()]
    }

    fun lookupRealIpForDomain(domain: String): String? {
      return domainToRealIp[domain.trim().trimEnd('.').lowercase()]
    }

    private val syntheticIpCounter = AtomicInteger(1)
    private val syntheticDomainToIp = ConcurrentHashMap<String, String>()
    private val syntheticIpToDomain = ConcurrentHashMap<String, String>()

    fun lookupSyntheticDomainForIp(hostOrIp: String): String? {
      return syntheticIpToDomain[hostOrIp.trim()]
    }

    fun clearMappingCaches() {
      realIpToDomain.clear()
      domainToRealIp.clear()
      syntheticDomainToIp.clear()
      syntheticIpToDomain.clear()
    }

    private fun allocateSyntheticIpForDomain(domain: String): String {
      val cleanDomain = domain.trim().trimEnd('.').lowercase()
      syntheticDomainToIp[cleanDomain]?.let { return it }
      if (syntheticDomainToIp.size >= MAX_MAPPING_ENTRIES) {
        syntheticDomainToIp.clear()
        syntheticIpToDomain.clear()
      }
      val seq = syntheticIpCounter.getAndIncrement() and 0x0FFFF
      val oct3 = (seq / 250) and 0xFF
      val oct4 = (seq % 250) + 2 // 2..251, never 0, 1 or 255
      val ip = "198.54.$oct3.$oct4"
      val existing = syntheticDomainToIp.putIfAbsent(cleanDomain, ip) ?: ip
      syntheticIpToDomain[existing] = cleanDomain
      return existing
    }

    private fun skipDnsNameStatic(buf: ByteArray, startOffset: Int): Int {
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
  }

  /**
   * The node accepted the stream but it produced no/closed reply. That is ambiguous (dead node vs.
   * dead destination, refused connection, stale pre-warmed transport) so it must NOT be counted as a
   * node transport failure.
   */
  private class SoftStreamFailure(message: String, val stalled: Boolean) : IOException(message)

  private data class OpenedTunnelWithReply(
    val connection: V2RayOutboundClient.TunnelConnection,
    val firstReplyBytes: ByteArray?,
    val firstReplyLen: Int,
    val nodeIndex: Int = 0,
  )

  private class PersistentDnsTunnelSlot(val dnsServerIp: String) {
    val lock = ReentrantLock()
    var connection: V2RayOutboundClient.TunnelConnection? = null

    fun closeLocked() {
      try {
        connection?.close()
      } catch (_: Exception) {}
      connection = null
    }
  }

  /**
   * Node pool. Replaced wholesale (never mutated) by [replaceServerPool]; code that works with
   * indices must snapshot it once (`val pool = serverPool`) so an index always refers to the pool
   * it was taken from.
   */
  @Volatile
  private var serverPool: List<V2RayConfig> =
    configs.ifEmpty {
      throw IllegalArgumentException("At least one V2RayConfig is required")
    }
  private val poolLock = Any()
  private val activeConfigIndex = AtomicInteger(0)
  private val consecutiveFailures = ConcurrentHashMap<Int, AtomicInteger>()
  private val penalizedIndices = ConcurrentHashMap.newKeySet<Int>()
  private val dnsCache = ConcurrentHashMap<String, ByteArray>()
  private val inFlightDnsLocks = ConcurrentHashMap<String, Any>()
  private val dnsSlotCounter = AtomicInteger(0)
  private val dnsTunnelSlots =
    arrayOf(
      PersistentDnsTunnelSlot("8.8.8.8"),
      PersistentDnsTunnelSlot("1.1.1.1"),
    )
  private val running = AtomicBoolean(false)

  /**
   * Bounded thread pool (`MAX_RELAY_THREADS`) to prevent OOM / unbounded blocking thread
   * explosion while still handling concurrent multi-stream apps.
   */
  private val relayExecutor: ExecutorService =
    ThreadPoolExecutor(
      16,
      MAX_RELAY_THREADS,
      30L,
      TimeUnit.SECONDS,
      SynchronousQueue(),
      { runnable ->
        Thread(runnable, "meh-proxy-worker").apply {
          isDaemon = true
        }
      },
      // Must throw: callers rely on the exception to close the client socket. Swallowing the
      // rejection would leave the connection open and silently hung.
      RejectedExecutionHandler { _, _ ->
        MehDiag.recordStreamRejected()
        throw RejectedExecutionException("meh-proxy worker pool saturated")
      },
    )

  private var serverSocket: ServerSocket? = null
  private var udpRelaySocket: DatagramSocket? = null

  var listenPort: Int = 0
    private set

  var udpListenPort: Int = 0
    private set

  val activeConfig: V2RayConfig
    get() {
      val pool = serverPool
      return pool[activeConfigIndex.get().coerceIn(0, pool.lastIndex)]
    }

  /** Snapshot of the current node pool (active node is `activeConfig`). */
  fun currentPool(): List<V2RayConfig> = serverPool

  fun start(): Int {
    val localhost = InetAddress.getByName("127.0.0.1")
    val server = ServerSocket(0, 512, localhost)
    serverSocket = server
    listenPort = server.localPort

    val udpServer = DatagramSocket(0, localhost)
    udpRelaySocket = udpServer
    udpListenPort = udpServer.localPort
    running.set(true)

    // Pre-warm ready TLS + WebSocket connections to the primary V2Ray node immediately
    V2RayOutboundClient.warmUpNodePoolAsync(
      config = activeConfig,
      protector = protector,
      targetCount = 4,
    )

    relayExecutor.execute {
      while (running.get() && !server.isClosed) {
        try {
          val client = server.accept()
          client.tcpNoDelay = true
          client.keepAlive = true
          client.soTimeout = 15_000
          try {
            relayExecutor.execute { handleClient(client) }
          } catch (_: Exception) {
            MehDiag.recordStreamRejected()
            try {
              client.close()
            } catch (_: Exception) {}
          }
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
          try {
            relayExecutor.execute {
              handleSocks5UdpDatagram(udpServer, dataCopy, clientAddr, clientPort)
            }
          } catch (_: Exception) {
            MehDiag.recordStreamRejected()
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
    closeAllPersistentDnsSlots()
    V2RayOutboundClient.clearAllPrewarmedTransports()
    serverSocket = null
    udpRelaySocket = null
    dnsCache.clear()
    inFlightDnsLocks.clear()
    consecutiveFailures.clear()
    penalizedIndices.clear()
    clearMappingCaches()
    try {
      relayExecutor.shutdownNow()
    } catch (_: Exception) {}
  }

  private fun closeAllPersistentDnsSlots() {
    for (slot in dnsTunnelSlots) {
      slot.lock.lock()
      try {
        slot.closeLocked()
      } finally {
        slot.lock.unlock()
      }
    }
  }

  /**
   * Explicitly switches the active server to the next healthy node in `serverPool` when
   * consecutive keep-alive probes fail or mid-stream stalls occur.
   */
  fun switchToNextHealthyNode(reason: String = "health_check"): V2RayConfig {
    val pool = serverPool
    if (pool.size <= 1) return activeConfig
    val oldIdx = activeConfigIndex.get().coerceIn(0, pool.lastIndex)
    val oldCfg = pool[oldIdx]
    penalizedIndices.add(oldIdx)
    if (penalizedIndices.size >= pool.size) {
      penalizedIndices.clear()
    }
    V2RayOutboundClient.evictPrewarmedTransports(oldCfg.endpointKey)

    var nextIdx = (oldIdx + 1) % pool.size
    for (step in 1 until pool.size) {
      val candidateIdx = (oldIdx + step) % pool.size
      if (candidateIdx !in penalizedIndices) {
        nextIdx = candidateIdx
        break
      }
    }

    // The pool may have been replaced while we were choosing; do not apply a stale index.
    if (pool !== serverPool) return activeConfig
    activeConfigIndex.set(nextIdx)
    consecutiveFailures[nextIdx]?.set(0)
    closeAllPersistentDnsSlots()
    MehDiag.recordNodeSwitch()
    if (reason == "keep_alive_timeout") {
      MehDiag.recordKeepAliveTriggeredFailover()
    }

    val newActive = pool[nextIdx]
    V2RayOutboundClient.warmUpNodePoolAsync(
      config = newActive,
      protector = protector,
      targetCount = 3,
    )
    return newActive
  }

  /**
   * Atomically replaces the node pool (best node first) without touching streams that are already
   * relaying: they keep their own node connection and finish normally, only *new* streams use the
   * new pool. Used by the background node refinement. Returns the new active node.
   */
  fun replaceServerPool(newConfigs: List<V2RayConfig>): V2RayConfig {
    if (newConfigs.isEmpty()) return activeConfig
    val newPool = newConfigs.distinctBy { it.endpointKey }
    val oldPool =
      synchronized(poolLock) {
        val previous = serverPool
        consecutiveFailures.clear()
        penalizedIndices.clear()
        activeConfigIndex.set(0)
        serverPool = newPool
        previous
      }
    val keptKeys = newPool.map { it.endpointKey }.toSet()
    for (old in oldPool) {
      if (old.endpointKey !in keptKeys) {
        V2RayOutboundClient.evictPrewarmedTransports(old.endpointKey)
      }
    }
    closeAllPersistentDnsSlots()
    MehDiag.recordNodeSwitch()
    if (running.get()) {
      V2RayOutboundClient.warmUpNodePoolAsync(
        config = newPool[0],
        protector = protector,
        targetCount = 4,
      )
    }
    return newPool[0]
  }

  private fun recordServerSuccess(idx: Int, pool: List<V2RayConfig>) {
    if (pool !== serverPool) return // pool was replaced mid-stream; idx is meaningless now
    consecutiveFailures[idx]?.set(0)
    penalizedIndices.remove(idx)
    val previous = activeConfigIndex.getAndSet(idx)
    if (previous != idx) {
      MehDiag.recordNodeSwitch()
      V2RayOutboundClient.warmUpNodePoolAsync(
        config = pool[idx],
        protector = protector,
        targetCount = 3,
      )
    }
  }

  private fun recordServerTransportFailure(idx: Int, pool: List<V2RayConfig>) {
    if (pool !== serverPool) return
    if (pool.size <= 1) return
    val count = consecutiveFailures.computeIfAbsent(idx) { AtomicInteger(0) }.incrementAndGet()
    if (count >= CONSECUTIVE_FAILURES_TO_PENALIZE) {
      penalizedIndices.add(idx)
      V2RayOutboundClient.evictPrewarmedTransports(pool[idx].endpointKey)
      if (penalizedIndices.size >= pool.size) {
        penalizedIndices.clear()
      }
      if (activeConfigIndex.get() == idx) {
        for (step in 1 until pool.size) {
          val candidateIdx = (idx + step) % pool.size
          if (candidateIdx !in penalizedIndices) {
            activeConfigIndex.set(candidateIdx)
            MehDiag.recordNodeSwitch()
            break
          }
        }
      }
    }
  }

  /**
   * Opens a V2Ray tunnel across `serverPool` with Mid-Stream First-Byte Verification:
   * - When `awaitFirstResponse == true` and `initialPayloadLen > 0` (e.g., TLS `ClientHello` or
   *   HTTP request), sends the initial payload and waits up to [firstReplyTimeoutMs] for the first
   *   response byte from the node.
   * - If the stream stays silent for [firstReplyTimeoutMs] or is closed before any reply, the
   *   next node is tried (at most [MAX_STALL_FAILOVER_NODES] nodes for silence). This is a *soft*
   *   failure: it does not penalize the node or change the active node, because a silent/closed
   *   stream may equally mean a dead destination. Only connect/handshake/write errors penalize.
   */
  private fun openTunnelWithVerifiedFailover(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 5500,
    initialPayload: ByteArray? = null,
    initialPayloadLen: Int = 0,
    awaitFirstResponse: Boolean = false,
    fallbackIpv4: String? = null,
    firstReplyTimeoutMs: Int = FIRST_BYTE_STALL_TIMEOUT_MS,
    maxNodes: Int = Int.MAX_VALUE,
    penalizeOnFailure: Boolean = true,
  ): OpenedTunnelWithReply {
    val pool = serverPool
    val poolSize = pool.size
    val currentPrimary = activeConfigIndex.get().coerceIn(0, poolSize - 1)

    val orderedIndices = ArrayList<Int>(poolSize)
    if (currentPrimary !in penalizedIndices) {
      orderedIndices.add(currentPrimary)
    }
    for (idx in 0 until poolSize) {
      if (idx !in penalizedIndices && idx !in orderedIndices) {
        orderedIndices.add(idx)
      }
    }
    for (idx in 0 until poolSize) {
      if (idx !in orderedIndices) {
        orderedIndices.add(idx)
      }
    }

    val cleanFallbackIp =
      if (!fallbackIpv4.isNullOrBlank() &&
        fallbackIpv4 != targetHost &&
        V2RayOutboundClient.parseIpv4Bytes(fallbackIpv4)?.let { V2RayOutboundClient.isPublicRoutableIpv4(it) } == true
      ) {
        fallbackIpv4
      } else {
        lookupRealIpForDomain(targetHost)
      }

    val targetsToTry =
      if (awaitFirstResponse && !cleanFallbackIp.isNullOrBlank() && cleanFallbackIp != targetHost) {
        listOf(targetHost, cleanFallbackIp)
      } else {
        listOf(targetHost)
      }

    var lastError: Exception? = null
    var stalledNodes = 0

    for ((attemptIdx, idx) in orderedIndices.withIndex()) {
      if (attemptIdx >= maxNodes) break
      val candidate = pool[idx]
      var hardFailure = false
      for (hostCandidate in targetsToTry) {
        var conn: V2RayOutboundClient.TunnelConnection? = null
        try {
          val connectTimeout = if (attemptIdx == 0) timeoutMs else 4000
          conn =
            V2RayOutboundClient.openTunnel(
              config = candidate,
              targetHost = hostCandidate,
              targetPort = targetPort,
              timeoutMs = connectTimeout,
              protector = protector,
              fallbackIpv4 = cleanFallbackIp,
              usePrewarmedPool = true,
            )
          if (initialPayload != null && initialPayloadLen > 0) {
            MehDiag.recordClientHelloSent()
            conn.outputStream.write(initialPayload, 0, initialPayloadLen)
            conn.outputStream.flush()
            MehDiag.recordBytesUploaded(initialPayloadLen.toLong())

            if (awaitFirstResponse) {
              val replyTimeout =
                if (stalledNodes == 0) firstReplyTimeoutMs else minOf(firstReplyTimeoutMs, FIRST_BYTE_RETRY_TIMEOUT_MS)
              conn.setReadTimeout(replyTimeout)
              val replyBuf = ByteArray(16384)
              var timedOut = false
              val replyLen =
                try {
                  conn.inputStream.read(replyBuf)
                } catch (_: SocketTimeoutException) {
                  timedOut = true
                  0
                }
              if (timedOut) {
                stalledNodes++
                val canTryAnotherNode =
                  stalledNodes < MAX_STALL_FAILOVER_NODES &&
                    attemptIdx + 1 < minOf(poolSize, maxNodes)
                if (canTryAnotherNode) {
                  MehDiag.recordFirstByteTimeoutFailover()
                  throw SoftStreamFailure("no reply from ${candidate.address} for $hostCandidate:$targetPort", stalled = true)
                }
                // Out of attempts: keep this stream open and let the relay keep waiting. The node
                // is NOT marked healthy or unhealthy: silence alone proves nothing.
                conn.setReadTimeout(NO_DATA_STREAM_TIMEOUT_MS)
                return OpenedTunnelWithReply(conn, null, 0, idx)
              }
              if (replyLen < 0) {
                MehDiag.recordFirstByteTimeoutFailover()
                throw SoftStreamFailure("V2Ray server ${candidate.address} closed stream before replying for $hostCandidate:$targetPort", stalled = false)
              }
              MehDiag.recordFirstByteReceived()
              MehDiag.recordBytesDownloaded(replyLen.toLong())
              conn.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
              recordServerSuccess(idx, pool)
              return OpenedTunnelWithReply(
                connection = conn,
                firstReplyBytes = replyBuf,
                firstReplyLen = replyLen,
                nodeIndex = idx,
              )
            }
          }
          conn.setReadTimeout(NO_DATA_STREAM_TIMEOUT_MS)
          recordServerSuccess(idx, pool)
          return OpenedTunnelWithReply(conn, null, 0, idx)
        } catch (e: Exception) {
          try {
            conn?.close()
          } catch (_: Exception) {}
          lastError = e
          if (e !is SoftStreamFailure) {
            hardFailure = true
          } else if (e.stalled) {
            // A timeout already cost a full wait; retrying the same node with the IP-form of the
            // target would only double it. Move on to the next node.
            break
          }
        }
      }
      if (hardFailure && penalizeOnFailure) {
        recordServerTransportFailure(idx, pool)
      }
    }
    throw lastError ?: IOException("All V2Ray servers in pool failed for $targetHost:$targetPort")
  }

  private fun handleClient(clientSocket: Socket) {
    MehDiag.onStreamOpened()
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
    } catch (_: Exception) {
    } finally {
      MehDiag.onStreamClosed()
    }
  }

  private fun readCompleteFirstClientPacket(
    clientSocket: Socket,
    clientIn: InputStream,
    buffer: ByteArray,
  ): Int {
    var totalRead =
      try {
        clientSocket.soTimeout = 1000
        val n = clientIn.read(buffer)
        if (n <= 0) return n
        n
      } catch (_: SocketTimeoutException) {
        return 0
      }

    if (totalRead >= 3 &&
      (buffer[0].toInt() and 0xFF) == 0x16 &&
      (buffer[1].toInt() and 0xFF) == 0x03 &&
      (buffer[2].toInt() and 0xFF) in 1..4
    ) {
      try {
        clientSocket.soTimeout = 180
        while (totalRead < 5) {
          val r = clientIn.read(buffer, totalRead, 5 - totalRead)
          if (r <= 0) break
          totalRead += r
        }
        if (totalRead >= 5) {
          val recordPayloadLen =
            ((buffer[3].toInt() and 0xFF) shl 8) or (buffer[4].toInt() and 0xFF)
          if (recordPayloadLen in 1..16384) {
            val expectedTotal = (5 + recordPayloadLen).coerceAtMost(buffer.size)
            while (totalRead < expectedTotal) {
              val r = clientIn.read(buffer, totalRead, expectedTotal - totalRead)
              if (r <= 0) break
              totalRead += r
            }
          }
        }
      } catch (_: SocketTimeoutException) {
        // Proceed with bytes read so far
      }
    }
    return totalRead
  }

  private fun handleLocalTcpDnsSession(
    clientSocket: Socket,
    clientIn: InputStream,
    clientOut: OutputStream,
  ) {
    clientSocket.soTimeout = 6000
    val lenBuf = ByteArray(2)
    while (running.get()) {
      if (!readExact(clientIn, lenBuf)) break
      val queryLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
      if (queryLen !in 12..4096) break
      val queryBytes = ByteArray(queryLen)
      if (!readExact(clientIn, queryBytes)) break
      val respBytes = resolveDnsOverV2Ray(queryBytes) ?: break
      val outFrame = ByteArray(2 + respBytes.size)
      outFrame[0] = ((respBytes.size ushr 8) and 0xFF).toByte()
      outFrame[1] = (respBytes.size and 0xFF).toByte()
      System.arraycopy(respBytes, 0, outFrame, 2, respBytes.size)
      clientOut.write(outFrame)
      clientOut.flush()
    }
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
        if (targetPort == 53) {
          clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
          clientOut.flush()
          handleLocalTcpDnsSession(clientSocket, clientIn, clientOut)
          return
        }

        val syntheticDomain = lookupSyntheticDomainForIp(rawTargetHost)
        val realMappedDomain = lookupDomainForRealIp(rawTargetHost)
        var effectiveHost = syntheticDomain ?: realMappedDomain ?: rawTargetHost

        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
        clientOut.flush()

        val firstBuffer = ByteArray(RELAY_BUFFER_SIZE)
        val firstLen = readCompleteFirstClientPacket(clientSocket, clientIn, firstBuffer)
        if (firstLen == -1) return

        var isTlsOrHttpPayload = false
        if (firstLen > 0) {
          val tlsSni = GfwKnockerXrayCore.extractTlsSniHostname(firstBuffer, firstLen)
          val httpHost = if (tlsSni == null) extractHttpHostHeader(firstBuffer, firstLen) else null
          val sniffedDomain = tlsSni ?: httpHost
          if (!sniffedDomain.isNullOrBlank()) {
            effectiveHost = sniffedDomain
            isTlsOrHttpPayload = true
          } else if (firstLen >= 3 && (firstBuffer[0].toInt() and 0xFF) == 0x16) {
            isTlsOrHttpPayload = true
          }
        }

        val ipv4Target = V2RayOutboundClient.parseIpv4Bytes(effectiveHost)
        if (ipv4Target != null && (ipv4Target[0].toInt() and 0xFF) == 10) {
          return
        }
        if (effectiveHost.contains(':')) {
          return
        }

        clientSocket.soTimeout = 0

        // Direct Split-Tunneling for Iranian Domains (.ir, Shaparak, Banks, Domestic apps) & Iranian IPs
        if (IranRoutingRules.isIranianDestination(effectiveHost, rawTargetHost)) {
          val directConn =
            try {
              IranRoutingRules.openDirectProtectedTunnel(
                targetHost = effectiveHost,
                targetPort = targetPort,
                timeoutMs = 5000,
                protector = protector,
                fallbackIpv4 = if (syntheticDomain != null) null else rawTargetHost,
              )
            } catch (_: Exception) {
              // Direct path failed (filtered/blocked site, DNS issue): fall back to the tunnel.
              null
            }

          if (directConn != null) {
            directConn.use { activeDirect ->
              if (firstLen > 0) {
                activeDirect.outputStream.write(firstBuffer, 0, firstLen)
                activeDirect.outputStream.flush()
                MehDiag.recordBytesUploaded(firstLen.toLong())
              }
              relayStreams(
                clientIn = clientIn,
                clientOut = clientOut,
                remoteIn = activeDirect.inputStream,
                remoteOut = activeDirect.outputStream,
                clientSocket = clientSocket,
                tunnelConnection = activeDirect,
              )
            }
            return
          }
        }

        // For TLS ClientHello / HTTP requests when multiple nodes exist in serverPool, verify first
        // response byte within FIRST_BYTE_STALL_TIMEOUT_MS so dead/frozen servers trigger instant failover.
        val verifyFirstByte =
          isTlsOrHttpPayload && firstLen > 0 && serverPool.size > 1 &&
            isReplaySafeInitialPayload(firstBuffer, firstLen)

        val opened =
          try {
            openTunnelWithVerifiedFailover(
              targetHost = effectiveHost,
              targetPort = targetPort,
              initialPayload = firstBuffer,
              initialPayloadLen = firstLen,
              awaitFirstResponse = verifyFirstByte,
              firstReplyTimeoutMs = FIRST_BYTE_STALL_TIMEOUT_MS,
              fallbackIpv4 = if (syntheticDomain != null) null else rawTargetHost,
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
            receivedInitialDownstreamByte = (opened.firstReplyLen > 0),
          )
        }
      }
      0x03 -> {
        clientSocket.soTimeout = 0
        val pHigh = ((udpListenPort ushr 8) and 0xFF).toByte()
        val pLow = (udpListenPort and 0xFF).toByte()
        clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, pHigh, pLow))
        clientOut.flush()
        try {
          while (running.get() && clientIn.read() != -1) {
            // Keep UDP control association open until client closes TCP control connection
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
   * True when re-sending [buf] to another node after a stall cannot duplicate a side effect:
   * a TLS record (ClientHello) or a plain-HTTP GET/HEAD.
   */
  private fun isReplaySafeInitialPayload(buf: ByteArray, len: Int): Boolean {
    if (len < 4) return false
    if ((buf[0].toInt() and 0xFF) == 0x16 && (buf[1].toInt() and 0xFF) == 0x03) return true
    val head = String(buf, 0, minOf(len, 5), Charsets.ISO_8859_1)
    return head.startsWith("GET ") || head.startsWith("HEAD ")
  }

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
   * - Port 53: Resolved via `resolveDnsOverV2Ray`.
   * - Iranian IPs/Domains: Relayed directly via a `udpProtector`-protected `DatagramSocket`.
   * - Port 443 (QUIC): Dropped so browsers/Instagram immediately use the 0-RTT pre-warmed TCP HTTP/2 pool.
   * - Other UDP ports (Voice calls, WebRTC, STUN, NTP, gaming): Relayed via VLESS UDP (`Command = 0x02`).
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
    val rawDstHost: String =
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
          val dom = String(packet, offset, len, Charsets.UTF_8)
          offset += len
          dom
        }
        0x04 -> {
          if (packet.size < offset + 18) return
          val ipv6Bytes = packet.copyOfRange(offset, offset + 16)
          offset += 16
          InetAddress.getByAddress(ipv6Bytes).hostAddress ?: return
        }
        else -> return
      }

    val dstPort = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    offset += 2

    val socksUdpHeader = packet.copyOfRange(0, offset)
    val udpPayload = packet.copyOfRange(offset, packet.size)
    if (udpPayload.isEmpty()) return

    // 1. DNS (UDP port 53)
    if (dstPort == 53) {
      if (udpPayload.size < 12) return
      MehDiag.recordUdpDnsPacket()
      val responsePayload = resolveDnsOverV2Ray(udpPayload) ?: return
      sendSocks5UdpReply(udpServer, socksUdpHeader, responsePayload, clientAddr, clientPort)
      return
    }

    val effectiveDstHost =
      lookupSyntheticDomainForIp(rawDstHost)
        ?: lookupDomainForRealIp(rawDstHost)
        ?: rawDstHost

    // 2. Direct UDP bypass for Iranian IPs & Domains
    if (IranRoutingRules.isIranianDestination(effectiveDstHost, rawDstHost)) {
      val directReply = relayDirectProtectedUdp(effectiveDstHost, rawDstHost, dstPort, udpPayload) ?: return
      MehDiag.recordUdpIranDirectPacket()
      sendSocks5UdpReply(udpServer, socksUdpHeader, directReply, clientAddr, clientPort)
      return
    }

    // 3. Drop UDP 443/8443 QUIC so HTTP/3 immediately falls back to our pre-warmed TCP HTTP/2 pool
    if (dstPort == 443 || dstPort == 8443) {
      MehDiag.recordUdpDroppedPacket()
      return
    }

    // 4. VLESS UDP (Command = 0x02) for voice calls, STUN/WebRTC, NTP, and custom UDP ports
    val vlessReply =
      V2RayOutboundClient.exchangeVlessUdpDatagram(
        config = activeConfig,
        targetHost = effectiveDstHost,
        targetPort = dstPort,
        udpPayload = udpPayload,
        timeoutMs = 3000,
        protector = protector,
      )
    if (vlessReply != null) {
      sendSocks5UdpReply(udpServer, socksUdpHeader, vlessReply, clientAddr, clientPort)
    } else {
      MehDiag.recordUdpDroppedPacket()
    }
  }

  private fun relayDirectProtectedUdp(
    effectiveHost: String,
    rawHost: String,
    dstPort: Int,
    payload: ByteArray,
  ): ByteArray? {
    return try {
      DatagramSocket().use { sock ->
        udpProtector(sock)
        sock.soTimeout = 2500
        val targetAddr =
          V2RayOutboundClient.parseIpv4Bytes(rawHost)?.let { InetAddress.getByAddress(it) }
            ?: IranRoutingRules.resolveIranianDomainDirectIpv4(effectiveHost)?.let { InetAddress.getByAddress(it) }
            ?: return null
        val outPkt = DatagramPacket(payload, payload.size, targetAddr, dstPort)
        sock.send(outPkt)
        MehDiag.recordBytesUploaded(payload.size.toLong())
        val inBuf = ByteArray(4096)
        val inPkt = DatagramPacket(inBuf, inBuf.size)
        sock.receive(inPkt)
        MehDiag.recordBytesDownloaded(inPkt.length.toLong())
        inBuf.copyOfRange(0, inPkt.length)
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun sendSocks5UdpReply(
    udpServer: DatagramSocket,
    socksUdpHeader: ByteArray,
    responsePayload: ByteArray,
    clientAddr: InetAddress,
    clientPort: Int,
  ) {
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

  private fun resolveDnsOverV2Ray(dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.size < 12) return null
    val startMs = System.currentTimeMillis()
    MehDiag.recordDnsQueryStart()

    val question = parseDnsQuestion(dnsQuery)
    if (question != null) {
      if (question.qtype == 28 || question.qtype == 65 || question.qtype == 64) {
        MehDiag.recordDnsSyntheticHit(System.currentTimeMillis() - startMs)
        return buildEmptyDnsNoerrorResponse(dnsQuery, question.questionEndOffset)
      }

      // Direct DNS Resolution for Iranian Domains (.ir, Shaparak, Banks, Domestic platforms)
      if (question.qtype == 1 && question.qclass == 1 && IranRoutingRules.isIranianDomain(question.domain)) {
        val iranIpv4 = IranRoutingRules.resolveIranianDomainDirectIpv4(question.domain)
        if (iranIpv4 != null) {
          val ipStr =
            "${iranIpv4[0].toInt() and 0xFF}.${iranIpv4[1].toInt() and 0xFF}.${iranIpv4[2].toInt() and 0xFF}.${iranIpv4[3].toInt() and 0xFF}"
          realIpToDomain[ipStr] = question.domain
          domainToRealIp[question.domain] = ipStr
          MehDiag.recordDnsIranDirectHit(System.currentTimeMillis() - startMs)
          return buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, iranIpv4)
        }
      }
    }

    if (question != null &&
      question.qtype == 1 &&
      question.qclass == 1 &&
      question.domain.isNotEmpty() &&
      activeConfig.protocol != V2RayProtocol.SERVERLESS
    ) {
      val fakeIpBytes = V2RayOutboundClient.parseIpv4Bytes(allocateSyntheticIpForDomain(question.domain))
      if (fakeIpBytes != null) {
        MehDiag.recordDnsSyntheticHit(System.currentTimeMillis() - startMs)
        return buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, fakeIpBytes)
      }
    }

    val cacheKey =
      if (question != null) {
        "${question.domain}:${question.qtype}:${question.qclass}"
      } else {
        null
      }

    if (cacheKey != null) {
      dnsCache[cacheKey]?.let { cached ->
        if (cached.size >= 12) {
          val copy = cached.copyOf()
          copy[0] = dnsQuery[0]
          copy[1] = dnsQuery[1]
          MehDiag.recordDnsCacheHit(System.currentTimeMillis() - startMs)
          return copy
        }
      }
    }

    val deadlineNanos = System.nanoTime() + DNS_BUDGET_MS * 1_000_000L
    val lock = if (cacheKey != null) inFlightDnsLocks.computeIfAbsent(cacheKey) { Any() } else Any()
    synchronized(lock) {
      try {
        if (cacheKey != null) {
          dnsCache[cacheKey]?.let { cached ->
            if (cached.size >= 12) {
              val copy = cached.copyOf()
              copy[0] = dnsQuery[0]
              copy[1] = dnsQuery[1]
              MehDiag.recordDnsCacheHit(System.currentTimeMillis() - startMs)
              return copy
            }
          }
        }

        if (activeConfig.protocol == V2RayProtocol.SERVERLESS) {
          val directDoh = resolveDnsOverHttpsProtectedDirect(dnsQuery)
          if (directDoh != null && isValidUnpoisonedDnsResponse(directDoh)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, directDoh)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = directDoh.copyOf()
            }
            MehDiag.recordDnsDirectDohSuccess(System.currentTimeMillis() - startMs)
            return directDoh
          }
        } else {
          val tcpDnsResp = resolveDnsOverTcpViaTunnel(dnsQuery, deadlineNanos)
          if (tcpDnsResp != null && isValidUnpoisonedDnsResponse(tcpDnsResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, tcpDnsResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = tcpDnsResp.copyOf()
            }
            MehDiag.recordDnsTunnelTcpSuccess(System.currentTimeMillis() - startMs)
            return tcpDnsResp
          }

          val dohTunnelResp = resolveDnsOverHttpsViaTunnel(dnsQuery, deadlineNanos)
          if (dohTunnelResp != null && isValidUnpoisonedDnsResponse(dohTunnelResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, dohTunnelResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = dohTunnelResp.copyOf()
            }
            MehDiag.recordDnsTunnelDohSuccess(System.currentTimeMillis() - startMs)
            return dohTunnelResp
          }
        }

        if (remainingDnsMillis(deadlineNanos) >= 2000) {
          val directDohResp = resolveDnsOverHttpsProtectedDirect(dnsQuery)
          if (directDohResp != null && isValidUnpoisonedDnsResponse(directDohResp)) {
            if (question != null) {
              recordRealDnsARecords(question.domain, directDohResp)
            }
            if (cacheKey != null && dnsCache.size < 2048) {
              dnsCache[cacheKey] = directDohResp.copyOf()
            }
            MehDiag.recordDnsDirectDohSuccess(System.currentTimeMillis() - startMs)
            return directDohResp
          }
        }
      } finally {
        if (cacheKey != null) {
          inFlightDnsLocks.remove(cacheKey, lock)
        }
      }
    }

    if (question != null && question.qtype == 1 && question.domain.isNotEmpty()) {
      val syntheticIp = allocateSyntheticIpForDomain(question.domain)
      val ipBytes = V2RayOutboundClient.parseIpv4Bytes(syntheticIp)
      if (ipBytes != null) {
        val syntheticResponse =
          buildSyntheticDnsAResponse(dnsQuery, question.questionEndOffset, ipBytes)
        if (cacheKey != null && dnsCache.size < 2048) {
          dnsCache[cacheKey] = syntheticResponse.copyOf()
        }
        MehDiag.recordDnsSyntheticHit(System.currentTimeMillis() - startMs)
        return syntheticResponse
      }
    }

    MehDiag.recordDnsServfail(System.currentTimeMillis() - startMs)
    return buildDnsServfailResponse(dnsQuery, question?.questionEndOffset ?: dnsQuery.size)
  }

  private fun remainingDnsMillis(deadlineNanos: Long): Int {
    val remaining = (deadlineNanos - System.nanoTime()) / 1_000_000L
    return remaining.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
  }

  private fun buildSyntheticDnsAResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int,
    ipv4Bytes: ByteArray,
  ): ByteArray {
    val safeEnd = questionEndOffset.coerceIn(12, dnsQuery.size)
    val respHeader = dnsQuery.copyOfRange(0, safeEnd)

    respHeader[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    respHeader[3] = 0x80.toByte()
    respHeader[4] = 0x00
    respHeader[5] = 0x01
    respHeader[6] = 0x00
    respHeader[7] = 0x01
    respHeader[8] = 0x00
    respHeader[9] = 0x00
    respHeader[10] = 0x00
    respHeader[11] = 0x00

    val finalOut = ByteArrayOutputStream(respHeader.size + 16)
    finalOut.write(respHeader)
    finalOut.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
    finalOut.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
    finalOut.write(byteArrayOf(0x00, 0x00, 0x00, 0x78))
    finalOut.write(byteArrayOf(0x00, 0x04))
    finalOut.write(ipv4Bytes)
    return finalOut.toByteArray()
  }

  private fun resolveDnsOverTcpViaTunnel(dnsQuery: ByteArray, deadlineNanos: Long): ByteArray? {
    val tcpFrame = ByteArray(2 + dnsQuery.size)
    tcpFrame[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
    tcpFrame[1] = (dnsQuery.size and 0xFF).toByte()
    System.arraycopy(dnsQuery, 0, tcpFrame, 2, dnsQuery.size)

    val startSlotIdx = (dnsSlotCounter.getAndIncrement() and 0x7FFFFFFF) % dnsTunnelSlots.size

    for (offset in dnsTunnelSlots.indices) {
      if (remainingDnsMillis(deadlineNanos) < 500) return null
      val slot = dnsTunnelSlots[(startSlotIdx + offset) % dnsTunnelSlots.size]
      if (slot.lock.tryLock()) {
        try {
          queryPersistentDnsSlotLocked(slot, tcpFrame, dnsQuery, deadlineNanos)?.let { return it }
        } finally {
          slot.lock.unlock()
        }
      }
    }

    if (remainingDnsMillis(deadlineNanos) < 500) return null
    val assignedSlot = dnsTunnelSlots[startSlotIdx]
    val lockWaitMs = remainingDnsMillis(deadlineNanos) - 500
    if (lockWaitMs <= 0 ||
      !assignedSlot.lock.tryLock(lockWaitMs.toLong(), TimeUnit.MILLISECONDS)
    ) {
      return null
    }
    try {
      queryPersistentDnsSlotLocked(assignedSlot, tcpFrame, dnsQuery, deadlineNanos)?.let { return it }
    } finally {
      assignedSlot.lock.unlock()
    }

    return null
  }

  private fun queryPersistentDnsSlotLocked(
    slot: PersistentDnsTunnelSlot,
    tcpFrame: ByteArray,
    dnsQuery: ByteArray,
    deadlineNanos: Long,
  ): ByteArray? {
    for (attempt in 0..1) {
      val remainingMs = remainingDnsMillis(deadlineNanos)
      if (remainingMs < 500) return null
      val attemptTimeout = minOf(remainingMs, DNS_SLOT_TIMEOUT_MS)
      try {
        var tunnel = slot.connection
        if (tunnel == null) {
          val opened =
            openTunnelWithVerifiedFailover(
              targetHost = slot.dnsServerIp,
              targetPort = 53,
              timeoutMs = attemptTimeout,
              initialPayload = tcpFrame,
              initialPayloadLen = tcpFrame.size,
              awaitFirstResponse = true,
              firstReplyTimeoutMs = attemptTimeout,
              maxNodes = 1,
              penalizeOnFailure = false,
            )
          tunnel = opened.connection
          slot.connection = tunnel

          val firstBytes = opened.firstReplyBytes
          val firstLen = opened.firstReplyLen
          if (firstBytes == null || firstLen <= 0) {
            slot.closeLocked()
            continue
          }
          val parsed = readDnsFrameFromStream(tunnel, firstBytes, firstLen, dnsQuery)
          if (parsed != null) {
            return parsed
          } else {
            slot.closeLocked()
            continue
          }
        } else {
          tunnel.setReadTimeout(attemptTimeout)
          tunnel.outputStream.write(tcpFrame)
          tunnel.outputStream.flush()
          val parsed = readDnsFrameFromStream(tunnel, null, 0, dnsQuery)
          if (parsed != null) {
            tunnel.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
            return parsed
          } else {
            slot.closeLocked()
          }
        }
      } catch (_: Exception) {
        slot.closeLocked()
      }
    }
    return null
  }

  private fun readDnsFrameFromStream(
    tunnel: V2RayOutboundClient.TunnelConnection,
    firstBytes: ByteArray?,
    firstLen: Int,
    dnsQuery: ByteArray,
  ): ByteArray? {
    val buf = ByteArrayOutputStream(512)
    if (firstBytes != null && firstLen > 0) {
      buf.write(firstBytes, 0, firstLen)
    }
    val tmp = ByteArray(512)

    while (buf.size() < 2) {
      val r = tunnel.inputStream.read(tmp)
      if (r <= 0) return null
      buf.write(tmp, 0, r)
    }
    val current = buf.toByteArray()
    val expectedDnsLen = ((current[0].toInt() and 0xFF) shl 8) or (current[1].toInt() and 0xFF)
    if (expectedDnsLen !in 12..4096) return null

    while (buf.size() < 2 + expectedDnsLen) {
      val r = tunnel.inputStream.read(tmp)
      if (r <= 0) return null
      buf.write(tmp, 0, r)
    }
    val full = buf.toByteArray()
    if (full.size >= 2 + expectedDnsLen) {
      val dnsResp = full.copyOfRange(2, 2 + expectedDnsLen)
      dnsResp[0] = dnsQuery[0]
      dnsResp[1] = dnsQuery[1]
      return dnsResp
    }
    return null
  }

  private fun resolveDnsOverHttpsViaTunnel(dnsQuery: ByteArray, deadlineNanos: Long): ByteArray? {
    for ((targetIp, sniHost) in listOf("8.8.8.8" to "dns.google", "1.1.1.1" to "cloudflare-dns.com")) {
      val remainingMs = remainingDnsMillis(deadlineNanos)
      if (remainingMs < 600) break
      try {
        val opened =
          openTunnelWithVerifiedFailover(
            targetHost = targetIp,
            targetPort = 443,
            timeoutMs = minOf(remainingMs, DNS_DOH_TIMEOUT_MS),
            maxNodes = 1,
            penalizeOnFailure = false,
          )
        opened.connection.use { tunnel ->
          val (tlsIn, tlsOut) =
            GfwKnockerXrayCore.openSslEngineOverStreams(
              sslContext = V2RayOutboundClient.createSmartSslContext(sniHost, allowInsecureFallback = true),
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
              sslContext = V2RayOutboundClient.createSmartSslContext(sniHost, allowInsecureFallback = true),
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
      if (offset < 0 || offset + 10 > dnsBytes.size) return false
      val type = ((dnsBytes[offset].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 1].toInt() and 0xFF)
      val rdLen = ((dnsBytes[offset + 8].toInt() and 0xFF) shl 8) or (dnsBytes[offset + 9].toInt() and 0xFF)
      offset += 10
      if (offset + rdLen > dnsBytes.size) return false
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
      val host = lookupDomainForRealIp(rawHost) ?: rawHost
      val port = target.substringAfterLast(":", "443").toIntOrNull() ?: 443
      if (host.isEmpty()) return

      val established = "HTTP/1.1 200 Connection Established\r\n\r\n"
      clientOut.write(established.toByteArray(Charsets.US_ASCII))
      clientOut.flush()

      val firstBuffer = ByteArray(RELAY_BUFFER_SIZE)
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

      if (IranRoutingRules.isIranianDestination(effectiveHost, rawHost)) {
        val directConn =
          try {
            IranRoutingRules.openDirectProtectedTunnel(
              targetHost = effectiveHost,
              targetPort = port,
              timeoutMs = 5000,
              protector = protector,
              fallbackIpv4 = rawHost,
            )
          } catch (_: Exception) {
            // Direct path failed (filtered/blocked site, DNS issue): fall back to the tunnel.
            null
          }
        if (directConn != null) {
          directConn.use { activeDirect ->
            if (firstLen > 0) {
              activeDirect.outputStream.write(firstBuffer, 0, firstLen)
              activeDirect.outputStream.flush()
              MehDiag.recordBytesUploaded(firstLen.toLong())
            }
            relayStreams(
              clientIn = clientIn,
              clientOut = clientOut,
              remoteIn = activeDirect.inputStream,
              remoteOut = activeDirect.outputStream,
              clientSocket = clientSocket,
              tunnelConnection = activeDirect,
            )
          }
          return
        }
      }

      val verifyFirstByte =
        firstLen > 0 && serverPool.size > 1 && isReplaySafeInitialPayload(firstBuffer, firstLen)
      val opened =
        openTunnelWithVerifiedFailover(
          targetHost = effectiveHost,
          targetPort = port,
          initialPayload = firstBuffer,
          initialPayloadLen = firstLen,
          awaitFirstResponse = verifyFirstByte,
          firstReplyTimeoutMs = FIRST_BYTE_STALL_TIMEOUT_MS,
          fallbackIpv4 = rawHost,
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
          receivedInitialDownstreamByte = (opened.firstReplyLen > 0),
        )
      }
    } else {
      val withoutHttp = target.removePrefix("http://").removePrefix("https://")
      val authority = withoutHttp.substringBefore("/")
      val path = "/" + withoutHttp.substringAfter("/", "")
      val rawHost = authority.substringBeforeLast(":").trim()
      val host = lookupDomainForRealIp(rawHost) ?: rawHost
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

      if (IranRoutingRules.isIranianDestination(host, rawHost)) {
        val directConn =
          try {
            IranRoutingRules.openDirectProtectedTunnel(
              targetHost = host,
              targetPort = port,
              timeoutMs = 5000,
              protector = protector,
              fallbackIpv4 = rawHost,
            )
          } catch (_: Exception) {
            // Direct path failed (filtered/blocked site, DNS issue): fall back to the tunnel.
            null
          }
        if (directConn != null) {
          directConn.use { activeDirect ->
            activeDirect.outputStream.write(rewrittenBytes)
            activeDirect.outputStream.flush()
            MehDiag.recordBytesUploaded(rewrittenBytes.size.toLong())
            relayStreams(
              clientIn = clientIn,
              clientOut = clientOut,
              remoteIn = activeDirect.inputStream,
              remoteOut = activeDirect.outputStream,
              clientSocket = clientSocket,
              tunnelConnection = activeDirect,
            )
          }
          return
        }
      }

      val opened =
        openTunnelWithVerifiedFailover(
          targetHost = host,
          targetPort = port,
          initialPayload = rewrittenBytes,
          initialPayloadLen = rewrittenBytes.size,
          awaitFirstResponse =
            serverPool.size > 1 && (method == "GET" || method == "HEAD"),
          firstReplyTimeoutMs = FIRST_BYTE_STALL_TIMEOUT_MS,
          fallbackIpv4 = rawHost,
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
          receivedInitialDownstreamByte = (opened.firstReplyLen > 0),
        )
      }
    }
  }

  private fun buildEmptyDnsNoerrorResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int = parseDnsQuestion(dnsQuery)?.questionEndOffset ?: dnsQuery.size,
  ): ByteArray {
    val safeLen = questionEndOffset.coerceIn(12, dnsQuery.size)
    val resp = dnsQuery.copyOfRange(0, safeLen)
    resp[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    resp[3] = 0x80.toByte()
    resp[4] = 0x00
    resp[5] = 0x01
    resp[6] = 0x00
    resp[7] = 0x00
    resp[8] = 0x00
    resp[9] = 0x00
    resp[10] = 0x00
    resp[11] = 0x00
    return resp
  }

  private fun buildDnsServfailResponse(
    dnsQuery: ByteArray,
    questionEndOffset: Int = parseDnsQuestion(dnsQuery)?.questionEndOffset ?: dnsQuery.size,
  ): ByteArray {
    val safeLen = questionEndOffset.coerceIn(12, dnsQuery.size)
    val resp = dnsQuery.copyOfRange(0, safeLen)
    resp[2] = ((dnsQuery[2].toInt() and 0x79) or 0x80).toByte()
    resp[3] = 0x82.toByte()
    resp[4] = 0x00
    resp[5] = 0x01
    resp[6] = 0x00
    resp[7] = 0x00
    resp[8] = 0x00
    resp[9] = 0x00
    resp[10] = 0x00
    resp[11] = 0x00
    return resp
  }

  /**
   * Full-duplex stream relay with:
   * - Shorter initial timeout (`NO_DATA_STREAM_TIMEOUT_MS = 14s`) before downstream data flows,
   *   upgrading to `IDLE_STREAM_TIMEOUT_MS = 45s` once bytes arrive.
   * - Immediate propagation of client socket closure (`closeOutbound()` / `close()`) to the remote
   *   node so closed streams never linger for 180 seconds.
   */
  private fun relayStreams(
    clientIn: InputStream,
    clientOut: OutputStream,
    remoteIn: InputStream,
    remoteOut: OutputStream,
    clientSocket: Socket? = null,
    tunnelConnection: V2RayOutboundClient.TunnelConnection? = null,
    receivedInitialDownstreamByte: Boolean = false,
  ) {
    try {
      clientSocket?.tcpNoDelay = true
      clientSocket?.keepAlive = true
      clientSocket?.soTimeout = IDLE_STREAM_TIMEOUT_MS
    } catch (_: Exception) {}

    var sawDownstreamData = receivedInitialDownstreamByte
    tunnelConnection?.setReadTimeout(
      if (sawDownstreamData) IDLE_STREAM_TIMEOUT_MS else NO_DATA_STREAM_TIMEOUT_MS
    )

    try {
      relayExecutor.execute {
        try {
          val buf = ByteArray(RELAY_BUFFER_SIZE)
          while (running.get()) {
            val n = clientIn.read(buf)
            if (n <= 0) break
            remoteOut.write(buf, 0, n)
            remoteOut.flush()
            MehDiag.recordBytesUploaded(n.toLong())
          }
          // Client finished sending (EOF): propagate half-close to the V2Ray node stream
          tunnelConnection?.closeOutbound()
        } catch (_: Exception) {
          if (clientSocket?.isClosed == true) {
            try {
              tunnelConnection?.close()
            } catch (_: Exception) {}
          } else {
            tunnelConnection?.closeOutbound()
          }
        }
      }
    } catch (_: Exception) {
      // No worker for the upload direction: a half-working stream would hang, so drop it.
      MehDiag.recordStreamRejected()
      try {
        clientSocket?.close()
      } catch (_: Exception) {}
      try {
        tunnelConnection?.close()
      } catch (_: Exception) {}
      return
    }

    try {
      val buf = ByteArray(RELAY_BUFFER_SIZE)
      while (running.get()) {
        val n = remoteIn.read(buf)
        if (n <= 0) break
        if (!sawDownstreamData) {
          sawDownstreamData = true
          MehDiag.recordFirstByteReceived()
          tunnelConnection?.setReadTimeout(IDLE_STREAM_TIMEOUT_MS)
        }
        clientOut.write(buf, 0, n)
        clientOut.flush()
        MehDiag.recordBytesDownloaded(n.toLong())
      }
    } catch (_: Exception) {
    } finally {
      try {
        clientSocket?.shutdownOutput()
      } catch (_: Exception) {}
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
