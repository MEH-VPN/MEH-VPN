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
      .connectTimeout(8, TimeUnit.SECONDS)
      .readTimeout(10, TimeUnit.SECONDS)
      .followRedirects(true)
      .build(),
) {

  companion object {
    /**
     * Official raw subscription endpoints from https://github.com/SoliSpirit/v2ray-configs
     * Ordered with Trojan and VLESS first for highest verified working rate.
     */
    val SOLISPIRIT_SOURCES =
      listOf(
        SubscriptionSource(
          name = "SoliSpirit/Trojan",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Sub1",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt",
        ),
        SubscriptionSource(
          name = "SoliSpirit/All",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
        ),
      )

    private const val WAVE_SIZE = 75
    private const val CONCURRENT_TEST_LIMIT = 30
  }

  /**
   * Fetches V2Ray configs from SoliSpirit/v2ray-configs on GitHub and filters to clean protocols
   * supported by the built-in V2Ray tunneling engine.
   */
  suspend fun fetchConfigsFromSoliSpirit(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()

      onLogUpdate("دریافت لیست سرور ها")

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
                if (V2RayOutboundClient.isSupportedByEngine(cfg) && !collected.containsKey(cfg.endpointKey)) {
                  collected[cfg.endpointKey] = cfg
                }
              }
            }
          }
        } catch (_: IOException) {
          // Continue trying remaining SoliSpirit subscription files
        }

        if (collected.size >= 400) {
          break
        }
      }

      collected.values.toList()
    }

  /**
   * Benchmarks candidate V2Ray nodes concurrently by opening a REAL V2Ray protocol tunnel
   * and sending an HTTP 204 connectivity probe (`http://cp.cloudflare.com/generate_204`)
   * through each server, returning the fastest node that actually proxies internet traffic.
   */
  suspend fun testAndSelectFastest(
    configs: List<V2RayConfig>,
    onLogUpdate: (String) -> Unit,
  ): V2RayConfig? =
    withContext(ioDispatcher) {
      val supported = configs.filter { V2RayOutboundClient.isSupportedByEngine(it) }.shuffled()
      if (supported.isEmpty()) return@withContext null

      val semaphore = Semaphore(CONCURRENT_TEST_LIMIT)
      val completedCount = AtomicInteger(0)

      onLogUpdate("تست سرور ها")

      val waves = supported.chunked(WAVE_SIZE).take(3)
      for (wave in waves) {
        coroutineContext.ensureActive()
        val verifiedWorkingNodes =
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
          }

        val bestInWave =
          verifiedWorkingNodes
            .sortedWith(
              compareBy<V2RayConfig> { it.latencyMs }
                .thenByDescending { it.speedScore }
            )
            .firstOrNull()

        if (bestInWave != null) {
          return@withContext bestInWave
        }
      }

      null
    }

  /**
   * Verifies real end-to-end V2Ray proxy connectivity (`GET /generate_204`) and measures round-trip speed.
   */
  fun measureNodeSpeed(config: V2RayConfig): V2RayConfig? {
    val realDelayMs = V2RayOutboundClient.measureRealProxyDelay(config, timeoutMs = 2600) ?: return null
    val score = 10_000.0 / realDelayMs.toDouble()
    return config.copy(
      latencyMs = realDelayMs,
      speedScore = score,
    )
  }
}
