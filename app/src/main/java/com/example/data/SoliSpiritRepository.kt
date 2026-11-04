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

/**
 * Single unified V2Ray connection method powered by the latest V2Ray / Xray-core engine.
 */
enum class MehConnectionMethod(
  val id: String,
  val titleFa: String,
  val subtitleFa: String,
  val badgeLabel: String,
) {
  V2RAY_SOLISPIRIT(
    id = "v2ray_solispirit",
    titleFa = "دریافت کانفیگ V2Ray",
    subtitleFa = "اتصال مستقیم و سریع با آخرین هسته V2Ray",
    badgeLabel = "V2Ray",
  ),
}

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

  /**
   * Executes the primary [MehConnectionMethod.V2RAY_SOLISPIRIT] and returns verified candidate configs.
   */
  suspend fun executeMethodAndSelectCandidates(
    method: MehConnectionMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
    maxCount: Int = 6,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      onLogUpdate("دریافت لیست سرور ها")
      val configs = fetchConfigsFromSoliSpirit(onLogUpdate)
      if (configs.isEmpty()) return@withContext emptyList()
      onLogUpdate("تست سرور ها")
      testAndSelectFastestCandidates(configs, maxCount = maxCount, onLogUpdate = onLogUpdate)
    }

  private fun fetchSingleSource(source: SubscriptionSource): List<V2RayConfig> {
    return try {
      val request =
        Request.Builder()
          .url(source.url)
          .header("User-Agent", "MEH-V2Ray-Android/26.10.3 (+https://github.com/SoliSpirit/v2ray-configs)")
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
   *    (`V2RayOutboundClient.verifyHttpsAndDnsCapability`) + Instagram + X/Twitter + Telegram DC2.
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

      val fullSocialPool = mutableListOf<V2RayConfig>()
      val partialSocialPool = mutableListOf<V2RayConfig>()
      val fallbackHttpsPool = mutableListOf<V2RayConfig>()
      val stage2Semaphore = Semaphore(6)

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
                compareBy<V2RayConfig> {
                  val noSniPenalty = if (it.sni.isBlank() && it.hostHeader.isBlank()) 120L else 0L
                  it.latencyMs + noSniPenalty
                }.thenByDescending { it.speedScore }
              )
          }

        if (stage1Passed.isEmpty()) continue

        val topToVerify = stage1Passed.take(12)
        val stage2Results =
          coroutineScope {
            topToVerify
              .map { candidate ->
                async {
                  stage2Semaphore.withPermit {
                    coroutineContext.ensureActive()
                    kotlinx.coroutines.withTimeoutOrNull(4800L) {
                      val httpsJob = async {
                        V2RayOutboundClient.verifyHttpsAndDnsCapability(
                          config = candidate,
                          timeoutMs = 3000,
                        )
                      }
                      val twitterJob = async {
                        V2RayOutboundClient.verifySocialMediaCapability(
                          config = candidate,
                          timeoutMs = 3000,
                        )
                      }
                      val instagramJob = async {
                        V2RayOutboundClient.verifyInstagramCapability(
                          config = candidate,
                          timeoutMs = 3000,
                        )
                      }
                      val tgJob = async {
                        V2RayOutboundClient.verifyTelegramCapability(
                          config = candidate,
                          timeoutMs = 2400,
                        )
                      }

                      val httpsLatency = httpsJob.await() ?: return@withTimeoutOrNull null
                      val twitterLatency = twitterJob.await()
                      val instagramLatency = instagramJob.await()
                      val tgLatency = tgJob.await()

                      val passedBothSocial = twitterLatency != null && instagramLatency != null
                      val passedAtLeastOneSocial = twitterLatency != null || instagramLatency != null

                      val effectiveLatency =
                        when {
                          passedBothSocial && tgLatency != null ->
                            (candidate.latencyMs + httpsLatency + twitterLatency!! + instagramLatency!! + tgLatency) / 5L
                          passedBothSocial ->
                            ((candidate.latencyMs + httpsLatency + twitterLatency!! + instagramLatency!!) / 4L) + 40L
                          passedAtLeastOneSocial -> {
                            val soc = twitterLatency ?: instagramLatency ?: httpsLatency
                            ((candidate.latencyMs + httpsLatency + soc) / 3L) + 200L
                          }
                          tgLatency != null ->
                            ((candidate.latencyMs + httpsLatency + tgLatency) / 3L) + 800L
                          else ->
                            ((candidate.latencyMs + httpsLatency) / 2L) + 1000L
                        }

                      val tier =
                        when {
                          passedBothSocial -> 1
                          passedAtLeastOneSocial -> 2
                          else -> 3
                        }

                      Pair(
                        tier,
                        candidate.copy(
                          latencyMs = effectiveLatency.coerceAtLeast(1L),
                          speedScore = 10_000.0 / effectiveLatency.coerceAtLeast(1L).toDouble(),
                        ),
                      )
                    }
                  }
                }
              }
              .awaitAll()
              .filterNotNull()
          }

        for ((tier, cfg) in stage2Results) {
          when (tier) {
            1 -> fullSocialPool.add(cfg)
            2 -> partialSocialPool.add(cfg)
            else -> fallbackHttpsPool.add(cfg)
          }
        }

        if (fullSocialPool.count { it.latencyMs < 550L } >= 4) {
          return@withContext selectDiverseCandidates(fullSocialPool, maxCount)
        }
      }

      when {
        fullSocialPool.isNotEmpty() -> selectDiverseCandidates(fullSocialPool + partialSocialPool, maxCount)
        partialSocialPool.isNotEmpty() -> selectDiverseCandidates(partialSocialPool, maxCount)
        else -> selectDiverseCandidates(fallbackHttpsPool, maxCount)
      }
    }

  private fun selectDiverseCandidates(
    pool: List<V2RayConfig>,
    maxCount: Int,
  ): List<V2RayConfig> {
    val unique = pool.distinctBy { it.endpointKey }.sortedBy { it.latencyMs }
    if (unique.size <= maxCount) return unique

    val selected = mutableListOf<V2RayConfig>()
    val subnetCounts = HashMap<String, Int>()
    val rootDomainCounts = HashMap<String, Int>()

    for (cfg in unique) {
      if (selected.size >= maxCount) break
      val ip = cfg.resolvedIp.ifBlank { cfg.address }
      val parts = ip.split(".")
      val subnetKey = if (parts.size == 4) "${parts[0]}.${parts[1]}" else ip
      val sniParts = cfg.sni.ifBlank { cfg.hostHeader }.ifBlank { cfg.address }.lowercase().split(".")
      val domainKey =
        if (sniParts.size >= 2) {
          "${sniParts[sniParts.size - 2]}.${sniParts[sniParts.size - 1]}"
        } else {
          cfg.sni.lowercase()
        }

      val sCount = subnetCounts.getOrDefault(subnetKey, 0)
      val dCount = rootDomainCounts.getOrDefault(domainKey, 0)
      if (sCount < 2 && dCount < 2) {
        selected.add(cfg)
        subnetCounts[subnetKey] = sCount + 1
        rootDomainCounts[domainKey] = dCount + 1
      }
    }

    if (selected.size < maxCount) {
      for (cfg in unique) {
        if (selected.size >= maxCount) break
        if (selected.none { it.endpointKey == cfg.endpointKey }) {
          selected.add(cfg)
        }
      }
    }

    return selected
  }

  suspend fun testAndSelectFastest(
    configs: List<V2RayConfig>,
    onLogUpdate: (String) -> Unit,
  ): V2RayConfig? =
    testAndSelectFastestCandidates(configs, maxCount = 1, onLogUpdate = onLogUpdate).firstOrNull()

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
