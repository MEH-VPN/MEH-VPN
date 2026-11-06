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
  val repoLabel: String = "SoliSpirit",
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
    val PRIMARY_RZASHAKERI_SOURCES =
      listOf(
        // Batch 1: Primary CDN & Raw endpoints from rzashakeri/v2ray-configs (Priority #1)
        SubscriptionSource(
          name = "RzaShakeri/VLESS-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Subscriptions/Sub1.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/AllSub-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/All_Configs_Sub.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        // Batch 2: Fastly & GCore mirrors for rzashakeri/v2ray-configs
        SubscriptionSource(
          name = "RzaShakeri/VLESS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Subscriptions/Sub1.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VLESS-GCore",
          url = "https://gcore.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        // Batch 3: Raw GitHub & root file endpoints for rzashakeri/v2ray-configs
        SubscriptionSource(
          name = "RzaShakeri/Trojan-GCore",
          url = "https://gcore.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VLESS-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/Protocols/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/Protocols/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/Subscriptions/Sub1.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/AllSub-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/All_Configs_Sub.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Tested-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/Tested.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
      )

    val FALLBACK_SOURCES =
      listOf(
        // Batch 1: Primary CDN endpoints from both SoliSpirit & MohammadBahemmat/V2ray-Collector
        SubscriptionSource(
          name = "Bahemmat/Tested-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/Tested.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "Bahemmat/VLESS-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/vless_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        // Batch 2: Trojan & Fastly mirrors from both repositories
        SubscriptionSource(
          name = "Bahemmat/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/trojan_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "Bahemmat/Tested-Fastly",
          url = "https://fastly.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/Tested.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-Fastly",
          url = "https://fastly.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        // Batch 3: Fastly & GCore mirrors for both repositories
        SubscriptionSource(
          name = "Bahemmat/VLESS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/vless_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "Bahemmat/Trojan-Fastly",
          url = "https://fastly.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/trojan_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-GCore",
          url = "https://gcore.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/trojan.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-GCore",
          url = "https://gcore.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        // Batch 4: GCore & Raw GitHub endpoints for both repositories
        SubscriptionSource(
          name = "Bahemmat/Tested-GCore",
          url = "https://gcore.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/Tested.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "Bahemmat/VLESS-GCore",
          url = "https://gcore.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/vless_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "Bahemmat/Tested-Raw",
          url = "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/Tested.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "Bahemmat/VLESS-Raw",
          url = "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/servers/vless_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        // Batch 5: Additional Raw & Sub endpoints
        SubscriptionSource(
          name = "Bahemmat/Trojan-Raw",
          url = "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/servers/trojan_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Trojan-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VLESS-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Sub1-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Subscriptions/Sub1.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/Sub1-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
      )

    /**
     * Combined list of all registered sources with `rzashakeri/v2ray-configs` as Priority #1,
     * followed by `SoliSpirit/v2ray-configs` and `MohammadBahemmat/V2ray-Collector`.
     */
    val SOLISPIRIT_SOURCES = PRIMARY_RZASHAKERI_SOURCES + FALLBACK_SOURCES

    private const val WAVE_SIZE = 80
    private const val CONCURRENT_TEST_LIMIT = 32
  }

  /**
   * Fetches configs exclusively from the Priority #1 repository (`rzashakeri/v2ray-configs`).
   */
  suspend fun fetchPrimaryConfigs(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      onLogUpdate("اتصال به مخزن اولویت اول (rzashakeri/v2ray-configs) ...")
      val configs = fetchFromSourceList(PRIMARY_RZASHAKERI_SOURCES)
      if (configs.isNotEmpty()) {
        onLogUpdate("${configs.size} سرور از مخزن اولویت اول دریافت شد")
      }
      configs
    }

  /**
   * Fetches configs from the fallback repositories (`SoliSpirit/v2ray-configs` and
   * `MohammadBahemmat/V2ray-Collector`) when Priority #1 is unavailable or fails verification.
   */
  suspend fun fetchFallbackConfigs(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      onLogUpdate("اتصال به مخازن پشتیبان (SoliSpirit و V2ray-Collector) ...")
      val configs = fetchFromSourceList(FALLBACK_SOURCES)
      if (configs.isNotEmpty()) {
        onLogUpdate("${configs.size} سرور از مخازن پشتیبان دریافت شد")
      }
      configs
    }

  private suspend fun fetchFromSourceList(
    sources: List<SubscriptionSource>,
  ): List<V2RayConfig> {
    val collected = LinkedHashMap<String, V2RayConfig>()
    val batches = sources.chunked(4)
    for ((batchIdx, batch) in batches.withIndex()) {
      coroutineContext.ensureActive()
      val batchResults =
        coroutineScope {
          batch
            .map { source ->
              async {
                val parsed = fetchSingleSource(source)
                Pair(source, parsed)
              }
            }
            .awaitAll()
        }
      for ((_, list) in batchResults) {
        for (cfg in list) {
          if (V2RayOutboundClient.isSupportedByEngine(cfg) && !collected.containsKey(cfg.endpointKey)) {
            collected[cfg.endpointKey] = cfg
          }
        }
      }
      if (batchIdx >= 1 && collected.size >= 380) {
        break
      }
    }
    return collected.values.toList()
  }

  /**
   * Fetches V2Ray configs starting with Priority #1 (`rzashakeri/v2ray-configs`), and automatically
   * falling back to `SoliSpirit/v2ray-configs` and `MohammadBahemmat/V2ray-Collector` if Priority #1
   * yields no configs.
   */
  suspend fun fetchConfigsFromSoliSpirit(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val primary = fetchPrimaryConfigs(onLogUpdate)
      if (primary.isNotEmpty()) {
        return@withContext primary
      }
      fetchFallbackConfigs(onLogUpdate)
    }

  /**
   * Priority-aware discovery and verification:
   * 1. First fetches and tests configs from `rzashakeri/v2ray-configs` (Priority #1).
   * 2. Only if Priority #1 returns no configs or none of its servers pass connection verification,
   *    fetches and tests configs from the fallback repositories (`SoliSpirit` & `V2ray-Collector`).
   */
  suspend fun executeMethodAndSelectCandidates(
    method: MehConnectionMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
    maxCount: Int = 6,
    prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      onLogUpdate("دریافت لیست سرور ها")
      val primaryConfigs = fetchPrimaryConfigs(onLogUpdate)
      if (primaryConfigs.isNotEmpty()) {
        onLogUpdate("تست سرور ها")
        val primaryVerified =
          testAndSelectFastestCandidates(
            configs = primaryConfigs,
            maxCount = maxCount,
            prioritizedSavedNodes = prioritizedSavedNodes,
            onLogUpdate = onLogUpdate,
          )
        if (primaryVerified.isNotEmpty()) {
          return@withContext primaryVerified
        }
        onLogUpdate("عدم اتصال سرورهای اولویت اول؛ بررسی مخازن پشتیبان ...")
      }

      val fallbackConfigs = fetchFallbackConfigs(onLogUpdate)
      if (fallbackConfigs.isEmpty() && prioritizedSavedNodes.isEmpty()) return@withContext emptyList()
      onLogUpdate("تست سرور ها")
      testAndSelectFastestCandidates(
        configs = fallbackConfigs,
        maxCount = maxCount,
        prioritizedSavedNodes = prioritizedSavedNodes,
        onLogUpdate = onLogUpdate,
      )
    }

  private fun fetchSingleSource(source: SubscriptionSource): List<V2RayConfig> {
    return try {
      val request =
        Request.Builder()
          .url(source.url)
          .header("User-Agent", "MEH-V2Ray-Android/26.10.3 (+https://github.com/rzashakeri/v2ray-configs)")
          .header("Accept", "text/plain, */*")
          .build()

      httpClient.newCall(request).execute().use { response ->
        if (!response.isSuccessful) return emptyList()
        val bodyText =
          response.body
            ?.charStream()
            ?.buffered()
            ?.useLines { lines -> lines.take(700).joinToString("\n") }
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
   * Two-stage benchmark with Prioritized Saved Healthy Nodes + Small Download Bandwidth Scoring:
   * 0. If [prioritizedSavedNodes] are provided, tests them first (Wave 0) and prepends them to the
   *    candidate list so known-good nodes are always evaluated first.
   * 1. Screens candidate V2Ray nodes concurrently with a fast HTTP 204 probe (`measureNodeSpeed`).
   * 2. Verifies the fastest candidates over TLS/HTTPS port 443 + Instagram + X/Twitter + Telegram DC2
   *    + a small (~16 KB) download bandwidth test (`measureSmallDownloadThroughputKbps`) so nodes
   *    are ranked by both latency AND real bandwidth.
   */
  suspend fun testAndSelectFastestCandidates(
    configs: List<V2RayConfig>,
    maxCount: Int = 6,
    prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
    maxWaves: Int = 3,
    concurrency: Int = CONCURRENT_TEST_LIMIT,
    verifyConcurrency: Int = 6,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val validSaved = prioritizedSavedNodes.filter { V2RayOutboundClient.isSupportedByEngine(it) }
      val savedKeys = validSaved.map { it.endpointKey }.toSet()
      val remainingSupported =
        configs
          .filter { V2RayOutboundClient.isSupportedByEngine(it) && it.endpointKey !in savedKeys }
          .shuffled()

      val supported = validSaved + remainingSupported
      if (supported.isEmpty()) return@withContext emptyList()

      val semaphore = Semaphore(concurrency.coerceAtLeast(1))
      val completedCount = AtomicInteger(0)

      onLogUpdate("شروع تست سرعت روی ${supported.size} سرور ...")

      val fullSocialPool = mutableListOf<V2RayConfig>()
      val partialSocialPool = mutableListOf<V2RayConfig>()
      val fallbackHttpsPool = mutableListOf<V2RayConfig>()
      val stage2Semaphore = Semaphore(verifyConcurrency.coerceAtLeast(1))

      val waves = supported.chunked(WAVE_SIZE).take(maxWaves.coerceAtLeast(1))
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
        onLogUpdate("بررسی کیفیت و پهنای باند سرورهای منتخب ...")

        val stage2Results =
          coroutineScope {
            topToVerify
              .map { candidate ->
                async {
                  stage2Semaphore.withPermit {
                    coroutineContext.ensureActive()
                    kotlinx.coroutines.withTimeoutOrNull(5200L) {
                      val httpsJob = async {
                        V2RayOutboundClient.verifyHttpsAndDnsCapability(
                          config = candidate,
                          timeoutMs = 3000,
                        )
                      }
                      val bandwidthJob = async {
                        V2RayOutboundClient.measureSmallDownloadThroughputKbps(
                          config = candidate,
                          timeoutMs = 2600,
                          targetBytes = 16_384,
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
                      val throughputKbps = bandwidthJob.await() ?: 45.0
                      val twitterLatency = twitterJob.await()
                      val instagramLatency = instagramJob.await()
                      val tgLatency = tgJob.await()

                      val passedBothSocial = twitterLatency != null && instagramLatency != null
                      val passedAtLeastOneSocial = twitterLatency != null || instagramLatency != null

                      val rawEffectiveLatency =
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

                      // Penalize choked/throttled nodes (< 15 KB/s) and reward high-throughput nodes
                      val bandwidthPenaltyMs = if (throughputKbps < 15.0) 350L else 0L
                      val effectiveLatency = (rawEffectiveLatency + bandwidthPenaltyMs).coerceAtLeast(1L)
                      val compositeScore =
                        (10_000.0 / effectiveLatency.toDouble()) +
                          (throughputKbps.coerceAtMost(2500.0) * 0.85)

                      val tier =
                        when {
                          passedBothSocial -> 1
                          passedAtLeastOneSocial -> 2
                          else -> 3
                        }

                      Pair(
                        tier,
                        candidate.copy(
                          latencyMs = effectiveLatency,
                          speedScore = compositeScore,
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
          val winners = selectDiverseCandidates(fullSocialPool, maxCount)
          onLogUpdate("بهترین سرور انتخاب شد (پینگ ${winners.first().latencyMs}ms)")
          return@withContext winners
        }
      }

      val finalSelection =
        when {
          fullSocialPool.isNotEmpty() -> selectDiverseCandidates(fullSocialPool + partialSocialPool, maxCount)
          partialSocialPool.isNotEmpty() -> selectDiverseCandidates(partialSocialPool, maxCount)
          else -> selectDiverseCandidates(fallbackHttpsPool, maxCount)
        }
      if (finalSelection.isNotEmpty()) {
        onLogUpdate("بهترین سرور انتخاب شد (پینگ ${finalSelection.first().latencyMs}ms)")
      }
      finalSelection
    }

  private fun selectDiverseCandidates(
    pool: List<V2RayConfig>,
    maxCount: Int,
  ): List<V2RayConfig> {
    val unique =
      pool
        .distinctBy { it.endpointKey }
        .sortedWith(
          compareByDescending<V2RayConfig> { it.speedScore }
            .thenBy { it.latencyMs }
        )
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
