package com.example.data

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.vpn.V2RayOutboundClient
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.coroutineContext
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

data class SubscriptionSource(
  val name: String,
  val url: String,
)

class SoliSpiritRepository(
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
  private val httpClient: OkHttpClient =
    OkHttpClient.Builder()
      .connectTimeout(7, TimeUnit.SECONDS)
      .readTimeout(9, TimeUnit.SECONDS)
      .followRedirects(true)
      .build(),
) {

  companion object {
    /**
     * Official raw subscription endpoints from https://github.com/SoliSpirit/v2ray-configs
     * with GitHub Raw + jsDelivr + Fastly + GCore CDN mirrors so configs are always reachable.
     */
    val SOLISPIRIT_SOURCES =
      listOf(
        SubscriptionSource(
          name = "SoliSpirit/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-Fastly",
          url = "https://fastly.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-GCore",
          url = "https://gcore.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-GCore",
          url = "https://gcore.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Sub1-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Subscriptions/Sub1.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Sub1-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt",
        ),
      )

    private const val WAVE_SIZE = 80
    private const val CONCURRENT_TEST_LIMIT = 32
  }

  /**
   * Fetches V2Ray configs from SoliSpirit/v2ray-configs on GitHub (and CDN mirrors in parallel)
   * and filters to clean protocols supported by the built-in V2Ray tunneling engine.
   */
  suspend fun fetchConfigsFromSoliSpirit(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()

      onLogUpdate("دریافت لیست سرور ها")

      val batches = SOLISPIRIT_SOURCES.chunked(4)
      for (batch in batches) {
        coroutineContext.ensureActive()
        val batchLists =
          coroutineScope {
            batch
              .map { source ->
                async {
                  fetchSingleSource(source)
                }
              }
              .awaitAll()
          }
        for (list in batchLists) {
          for (cfg in list) {
            if (V2RayOutboundClient.isSupportedByEngine(cfg) && !collected.containsKey(cfg.endpointKey)) {
              collected[cfg.endpointKey] = cfg
            }
          }
        }
        if (collected.size >= 250) {
          break
        }
      }

      collected.values.toList()
    }

  private fun fetchSingleSource(source: SubscriptionSource): List<V2RayConfig> {
    return try {
      val request =
        Request.Builder()
          .url(source.url)
          .header("User-Agent", "MEH-V2Ray-Android/1.0 (+https://github.com/SoliSpirit/v2ray-configs)")
          .header("Accept", "text/plain, */*")
          .build()

      httpClient.newCall(request).execute().use { response ->
        if (!response.isSuccessful) return emptyList()
        val bodyText =
          response.body
            ?.charStream()
            ?.buffered()
            ?.useLines { lines -> lines.take(600).joinToString("\n") }
            .orEmpty()
        V2RayConfigParser.parseSubscriptionContent(bodyText)
      }
    } catch (_: IOException) {
      emptyList()
    } catch (_: Exception) {
      emptyList()
    }
  }

  /**
   * Two-stage benchmark:
   * 1. Screens candidate V2Ray nodes concurrently with a fast HTTP 204 probe (`measureNodeSpeed`).
   * 2. Verifies the fastest candidates with a 2nd independent connection over TLS/HTTPS port 443
   *    (`V2RayOutboundClient.verifyHttpsAndDnsCapability`) to filter out rate-limited or broken nodes
   *    that pass a single port-80 probe but drop real app HTTPS traffic.
   */
  suspend fun testAndSelectFastestCandidates(
    configs: List<V2RayConfig>,
    maxCount: Int = 6,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val supported = configs.filter { V2RayOutboundClient.isSupportedByEngine(it) }.shuffled()
      if (supported.isEmpty()) return@withContext emptyList()

      val semaphore = Semaphore(CONCURRENT_TEST_LIMIT)
      val completedCount = AtomicInteger(0)

      onLogUpdate("تست سرور ها")

      val verifiedPool = mutableListOf<V2RayConfig>()
      val stage1Fallbacks = mutableListOf<V2RayConfig>()

      val waves = supported.chunked(WAVE_SIZE).take(3)
      for (wave in waves) {
        coroutineContext.ensureActive()
        val stage1Passed =
          coroutineScope {
            wave
              .map { config ->
                async {
                  semaphore.withPermit {
                    coroutineContext.ensureActive()
                    val measured = measureNodeSpeed(config)
                    completedCount.incrementAndGet()
                    measured
                  }
                }
              }
              .awaitAll()
              .filterNotNull()
              .sortedWith(
                compareBy<V2RayConfig> { it.latencyMs }
                  .thenByDescending { it.speedScore }
              )
          }

        if (stage1Passed.isEmpty()) continue
        stage1Fallbacks.addAll(stage1Passed)

        // Stage 2: Verify real HTTPS (Google) AND raw IP connection to Telegram DC2 (149.154.167.50:443)
        val topToVerify = stage1Passed.take(16)
        val stage2Verified =
          coroutineScope {
            topToVerify
              .map { candidate ->
                async {
                  coroutineContext.ensureActive()
                  val httpsLatency =
                    V2RayOutboundClient.verifyHttpsAndDnsCapability(
                      config = candidate,
                      timeoutMs = 3000,
                    ) ?: return@async null

                  val tgLatency =
                    V2RayOutboundClient.verifyTelegramCapability(
                      config = candidate,
                      timeoutMs = 2400,
                    )

                  val effectiveLatency =
                    if (tgLatency != null) {
                      (candidate.latencyMs + httpsLatency + tgLatency) / 3L
                    } else {
                      (candidate.latencyMs + httpsLatency) / 2L
                    }

                  candidate.copy(
                    latencyMs = effectiveLatency.coerceAtLeast(1L),
                    speedScore = 10_000.0 / effectiveLatency.coerceAtLeast(1L).toDouble(),
                  )
                }
              }
              .awaitAll()
              .filterNotNull()
              .sortedBy { it.latencyMs }
          }

        verifiedPool.addAll(stage2Verified)
        if (verifiedPool.isNotEmpty()) {
          return@withContext verifiedPool
            .distinctBy { it.endpointKey }
            .sortedBy { it.latencyMs }
            .take(maxCount)
        }
      }

      stage1Fallbacks
        .distinctBy { it.endpointKey }
        .sortedBy { it.latencyMs }
        .take(maxCount)
    }

  suspend fun testAndSelectFastest(
    configs: List<V2RayConfig>,
    onLogUpdate: (String) -> Unit,
  ): V2RayConfig? =
    testAndSelectFastestCandidates(configs, maxCount = 1, onLogUpdate = onLogUpdate).firstOrNull()

  /**
   * Verifies real end-to-end V2Ray proxy connectivity (`GET /generate_204`) and measures round-trip speed.
   */
  fun measureNodeSpeed(config: V2RayConfig): V2RayConfig? {
    val resolvedIp = V2RayOutboundClient.resolveEndpointIpv4(config.address) ?: return null
    val withIp = config.copy(resolvedIp = resolvedIp)
    val realDelayMs = V2RayOutboundClient.measureRealProxyDelay(withIp, timeoutMs = 2600) ?: return null
    val score = 10_000.0 / realDelayMs.toDouble()
    return withIp.copy(
      latencyMs = realDelayMs,
      speedScore = score,
    )
  }
}
