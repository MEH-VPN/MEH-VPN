package com.example.data

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.coroutineContext
import kotlin.system.measureNanoTime

data class SubscriptionSource(
  val name: String,
  val url: String,
)

class SoliSpiritRepository(
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
  private val httpClient: OkHttpClient =
    OkHttpClient.Builder()
      .connectTimeout(8, TimeUnit.SECONDS)
      .readTimeout(10, TimeUnit.SECONDS)
      .followRedirects(true)
      .build(),
) {

  companion object {
    /**
     * Official raw subscription endpoints from https://github.com/SoliSpirit/v2ray-configs
     */
    val SOLISPIRIT_SOURCES =
      listOf(
        SubscriptionSource(
          name = "SoliSpirit/Sub1",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VMess",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vmess.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/SS",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/ss.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/All",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
        ),
      )

    private const val MAX_CANDIDATES_TO_TEST = 42
    private const val SOCKET_TIMEOUT_MS = 1400
    private const val CONCURRENT_TEST_LIMIT = 14
  }

  /**
   * Fetches V2Ray configs from SoliSpirit/v2ray-configs on GitHub and reports live progress.
   */
  suspend fun fetchConfigsFromSoliSpirit(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()

      onLogUpdate("در حال دریافت کانفیگ از SoliSpirit/v2ray-configs...")

      for (source in SOLISPIRIT_SOURCES) {
        coroutineContext.ensureActive()
        try {
          val request =
            Request.Builder()
              .url(source.url)
              .header("User-Agent", "MEH-V2Ray-Android/1.0 (+https://github.com/SoliSpirit/v2ray-configs)")
              .header("Accept", "text/plain, */*")
              .build()

          httpClient.newCall(request).execute().use { response ->
            if (response.isSuccessful) {
              val bodyText = response.body?.string().orEmpty()
              val parsed = V2RayConfigParser.parseSubscriptionContent(bodyText)
              for (cfg in parsed) {
                if (!collected.containsKey(cfg.endpointKey)) {
                  collected[cfg.endpointKey] = cfg
                }
              }
              if (collected.isNotEmpty()) {
                onLogUpdate("دریافت ${collected.size} کانفیگ از ${source.name}...")
              }
            }
          }
        } catch (_: IOException) {
          // Continue trying remaining SoliSpirit subscription mirrors/files
        }

        // Once we have a rich pool of diverse configs across protocols, no need to download huge redundant files
        if (collected.size >= 160) {
          break
        }
      }

      collected.values.toList()
    }

  /**
   * Benchmarks candidate V2Ray nodes concurrently using real TCP socket handshake + double-probe
   * speed scoring, emitting live progress to the single-line log and returning the fastest node.
   */
  suspend fun testAndSelectFastest(
    configs: List<V2RayConfig>,
    onLogUpdate: (String) -> Unit,
  ): V2RayConfig? =
    withContext(ioDispatcher) {
      if (configs.isEmpty()) return@withContext null

      // Pick a balanced sample across VLESS, VMess, Trojan, SS for speed testing
      val candidates =
        configs
          .shuffled()
          .sortedBy {
            when (it.protocol) {
              com.example.model.V2RayProtocol.VLESS -> 0
              com.example.model.V2RayProtocol.TROJAN -> 1
              com.example.model.V2RayProtocol.VMESS -> 2
              com.example.model.V2RayProtocol.SHADOWSOCKS -> 3
            }
          }
          .take(MAX_CANDIDATES_TO_TEST)

      val total = candidates.size
      val completedCount = AtomicInteger(0)
      val bestPingSoFar = AtomicLong(Long.MAX_VALUE)
      val semaphore = Semaphore(CONCURRENT_TEST_LIMIT)

      onLogUpdate("شروع تست سرعت روی $total کانفیگ منتخب...")

      val testedNodes =
        coroutineScope {
          candidates
            .map { config ->
              async {
                semaphore.withPermit {
                  coroutineContext.ensureActive()
                  val measured = measureNodeSpeed(config)
                  val done = completedCount.incrementAndGet()

                  if (measured != null) {
                    val currentBest = bestPingSoFar.get()
                    if (measured.latencyMs < currentBest) {
                      bestPingSoFar.compareAndSet(currentBest, measured.latencyMs)
                    }
                  }

                  val bestText =
                    bestPingSoFar.get().let {
                      if (it < Long.MAX_VALUE) " • بهترین: ${it}ms" else ""
                    }
                  onLogUpdate("در حال تست سرعت ($done/$total)$bestText...")
                  measured
                }
              }
            }
            .awaitAll()
            .filterNotNull()
        }

      // Sort by lowest latency and highest stability speed score
      testedNodes
        .sortedWith(
          compareBy<V2RayConfig> { it.latencyMs }
            .thenByDescending { it.speedScore }
        )
        .firstOrNull()
    }

  /**
   * Performs a real TCP socket connection and verifies round-trip handshake responsiveness.
   */
  fun measureNodeSpeed(config: V2RayConfig): V2RayConfig? {
    return try {
      var firstConnectMs = 0L
      val nanos1 =
        measureNanoTime {
          Socket().use { socket ->
            socket.tcpNoDelay = true
            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.connect(InetSocketAddress(config.address, config.port), SOCKET_TIMEOUT_MS)
          }
        }
      firstConnectMs = (nanos1 / 1_000_000L).coerceAtLeast(1L)

      // Perform a fast second verification probe for top-tier responsive servers to measure jitter/speed
      val finalLatencyMs =
        if (firstConnectMs < 650L) {
          val nanos2 =
            measureNanoTime {
              Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.soTimeout = SOCKET_TIMEOUT_MS
                socket.connect(InetSocketAddress(config.address, config.port), SOCKET_TIMEOUT_MS)
              }
            }
          val secondConnectMs = (nanos2 / 1_000_000L).coerceAtLeast(1L)
          ((firstConnectMs + secondConnectMs) / 2L).coerceAtLeast(1L)
        } else {
          firstConnectMs
        }

      val score = 10_000.0 / finalLatencyMs.toDouble()
      config.copy(
        latencyMs = finalLatencyMs,
        speedScore = score,
      )
    } catch (_: Exception) {
      null
    }
  }
}
