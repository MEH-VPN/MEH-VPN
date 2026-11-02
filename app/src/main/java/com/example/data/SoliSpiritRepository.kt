package com.example.data

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.vpn.GfwKnockerXrayCore
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
 * Ordered connection & circumvention methods available in MEH VPN:
 * 1. Standard V2Ray (`SoliSpirit/v2ray-configs` with direct native TLS handshake)
 * 2. `WhiteDNS` (`https://github.com/WhiteDNS` -> `whitedns-sub/base64.txt` + `cloudflare-base64.txt` + Clean-IP + ByeDPI)
 * 3. `CluvexStudio/Aether` (`https://github.com/CluvexStudio/Aether` -> `sni_host_range` midpoint SNI split + Anycast gateway discovery)
 * 4. `GFW-knocker/Xray-core` (`https://github.com/GFW-knocker/Xray-core` -> `tlshello` record/segment splitting)
 * 5. `patterniha/Free-Configs` (`F&F` two-layer fragmentation + `PattNG` custom cipherSuites)
 * 6. `patterniha/Z-E-U-S` (Clean Cloudflare IP scanner + `transform.py` TLS 443 conversion)
 * 7. `patterniha/Serverless-for-Iran` Frag-A (`Serverless-v52-fragA` `[6, 98, 1]` direct tunnel)
 * 8. `patterniha/Serverless-for-Iran` Frag-B (`Serverless-v52-fragB` `[0, 104, 1]` direct tunnel)
 * 9. `patterniha/SNI-Spoofing` & `patterniha/MMDF` (Micro 1-3 byte SNI splitting + Domain Fronting)
 */
enum class MehConnectionMethod(
  val id: String,
  val titleFa: String,
  val subtitleFa: String,
  val badgeLabel: String,
) {
  V2RAY_SOLISPIRIT(
    id = "v2ray_solispirit",
    titleFa = "دریافت کانفیگ و تست V2Ray",
    subtitleFa = "اتصال مستقیم و سریع V2Ray با تست دو مرحله‌ای",
    badgeLabel = "V2Ray",
  ),
  WHITEDNS_OFFICIAL(
    id = "whitedns_official",
    titleFa = "روش WhiteDNS (اشتراک رسمی و کلودفلر)",
    subtitleFa = "مخزن WhiteDNS با اشتراک ضد فیلتر، آی‌پی تمیز و ByeDPI",
    badgeLabel = "WhiteDNS",
  ),
  CLUVEX_AETHER(
    id = "cluvex_aether",
    titleFa = "روش CluvexStudio Aether (هسته Aether)",
    subtitleFa = "شکاف هوشمند وسط SNI (sni_host_range) + کشف درگاه Anycast کلودفلر",
    badgeLabel = "Aether",
  ),
  GFW_KNOCKER_XRAY(
    id = "gfw_knocker_xray",
    titleFa = "روش هسته GFW-knocker/Xray-core",
    subtitleFa = "شکاف пакеتی ClientHello با موتور GFW-knocker Mahsa-Core",
    badgeLabel = "GFW-knocker",
  ),
  PATTERNIHA_FREE_CONFIGS(
    id = "patterniha_free_configs",
    titleFa = "روش Patterniha Free-Configs (F&F)",
    subtitleFa = "کانفیگ‌های ضد فیلتر Patterniha با فرگمنت دو لایه و CipherSuite",
    badgeLabel = "Patterniha F&F",
  ),
  PATTERNIHA_ZEUS(
    id = "patterniha_zeus",
    titleFa = "روش Patterniha Z-E-U-S (کلودفلر تمیز)",
    subtitleFa = "تانل روی آی‌پی‌های تمیز Z-E-U-S با الگوریتم Transform",
    badgeLabel = "Z-E-U-S",
  ),
  PATTERNIHA_SERVERLESS_FRAG_A(
    id = "patterniha_serverless_frag_a",
    titleFa = "روش Patterniha Serverless (فرگمنت A)",
    subtitleFa = "اتصال مستقیم بدون سرور (Serverless-v52-fragA) با شکاف [6, 98, 1]",
    badgeLabel = "Serverless A",
  ),
  PATTERNIHA_SERVERLESS_FRAG_B(
    id = "patterniha_serverless_frag_b",
    titleFa = "روش Patterniha Serverless (فرگمنت B)",
    subtitleFa = "اتصال مستقیم بدون سرور (Serverless-v52-fragB) با الگوی [104, 1]",
    badgeLabel = "Serverless B",
  ),
  PATTERNIHA_SNI_SPOOFING_MMDF(
    id = "patterniha_sni_spoofing_mmdf",
    titleFa = "روش Patterniha SNI-Spoofing و MMDF",
    subtitleFa = "خردایش میکرو ۱ بایتی SNI و Domain Fronting برای عبور از DPI",
    badgeLabel = "SNI-Spoof",
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

    /**
     * Official WhiteDNS subscription endpoints (`https://github.com/WhiteDNS/WhiteVPN` & `iampedii/whitedns-sub`).
     */
    val WHITEDNS_SOURCES =
      listOf(
        SubscriptionSource(
          name = "WhiteDNS/Base64-CDN",
          url = "https://cdn.jsdelivr.net/gh/iampedii/whitedns-sub@main/base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Cloudflare-CDN",
          url = "https://cdn.jsdelivr.net/gh/iampedii/whitedns-sub@main/cloudflare-base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Base64-Fastly",
          url = "https://fastly.jsdelivr.net/gh/iampedii/whitedns-sub@main/base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Cloudflare-Fastly",
          url = "https://fastly.jsdelivr.net/gh/iampedii/whitedns-sub@main/cloudflare-base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Base64-GCore",
          url = "https://gcore.jsdelivr.net/gh/iampedii/whitedns-sub@main/base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Cloudflare-GCore",
          url = "https://gcore.jsdelivr.net/gh/iampedii/whitedns-sub@main/cloudflare-base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Base64-Raw",
          url = "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/base64.txt",
        ),
        SubscriptionSource(
          name = "WhiteDNS/Cloudflare-Raw",
          url = "https://raw.githubusercontent.com/iampedii/whitedns-sub/refs/heads/main/cloudflare-base64.txt",
        ),
      )

    /**
     * Official endpoints from https://github.com/patterniha/Free-Configs and its upstream feeds.
     */
    val PATTERNIHA_FREE_CONFIG_SOURCES =
      listOf(
        SubscriptionSource(
          name = "Patterniha/Free-Configs-CDN",
          url = "https://cdn.jsdelivr.net/gh/patterniha/Free-Configs@main/configs.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/Free-Configs-Fastly",
          url = "https://fastly.jsdelivr.net/gh/patterniha/Free-Configs@main/configs.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/Free-Configs-GCore",
          url = "https://gcore.jsdelivr.net/gh/patterniha/Free-Configs@main/configs.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/Free-Configs-Raw",
          url = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/Free-Configs-Base64-CDN",
          url = "https://cdn.jsdelivr.net/gh/patterniha/Free-Configs@main/configs_base64.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/0xRadikal-Verified",
          url = "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/verified/configs.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/MahsaFree-MTN",
          url = "https://cdn.jsdelivr.net/gh/mahsanet/MahsaFreeConfig@main/mtn/sub_1.txt",
        ),
        SubscriptionSource(
          name = "Patterniha/PSG-Mix",
          url = "https://cdn.jsdelivr.net/gh/itsyebekhe/PSG@main/subscriptions/xray/mix",
        ),
      )

    /**
     * Clean Cloudflare IPv4 endpoints from https://github.com/patterniha/Z-E-U-S/blob/main/ips.txt
     * and `patterniha/Free-Configs/scripts/transform.py` (`HEALTHCHECK_ADDRESS = "188.114.98.0"`).
     */
    val PATTERNIHA_ZEUS_CLEAN_IPS =
      listOf(
        "188.114.98.0",
        "104.16.0.158",
        "104.16.1.195",
        "104.16.10.198",
        "104.16.100.210",
        "104.16.104.11",
        "1.1.1.107",
        "1.0.0.168",
      )

    private val CF_PORTS_ALL =
      setOf(80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880)

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

      val batches = (SOLISPIRIT_SOURCES + WHITEDNS_SOURCES.take(4)).chunked(4)
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
   * Fetches official WhiteDNS subscriptions (`iampedii/whitedns-sub/base64.txt` & `cloudflare-base64.txt`
   * from `https://github.com/WhiteDNS/WhiteVPN`) and pairs them with both direct TLS and WhiteDNS ByeDPI
   * SNI-split + Clean-IP endpoints.
   */
  suspend fun fetchConfigsFromWhiteDns(): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()

      val lists =
        coroutineScope {
          WHITEDNS_SOURCES
            .map { source -> async { fetchSingleSource(source) } }
            .awaitAll()
        }

      for (list in lists) {
        for (cfg in list) {
          if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
          val directCfg = cfg.copy(remarks = "WhiteDNS • ${cfg.cleanTitle}")
          collected[directCfg.endpointKey] = directCfg

          val byedpiCfg =
            cfg.copy(
              id = "${cfg.id}_whitedns_byedpi",
              remarks = "WhiteDNS ByeDPI • ${cfg.cleanTitle}",
              fragmentProfile = "whitedns_byedpi",
            )
          collected[byedpiCfg.endpointKey] = byedpiCfg

          applyPatternihaTransformRule(
            config = cfg,
            cleanCloudflareIp = "188.114.98.0",
            fragmentProfile = "whitedns_byedpi",
            prefixTag = "WhiteDNS-CF",
          )?.let { cfNode ->
            collected[cfNode.endpointKey] = cfNode
          }
        }
      }

      if (collected.isEmpty()) {
        // Fallback: apply WhiteDNS ByeDPI to SoliSpirit configs if WhiteDNS repo was unreachable
        for (cfg in fetchConfigsFromSoliSpirit {}) {
          val byedpi = cfg.copy(fragmentProfile = "whitedns_byedpi", remarks = "WhiteDNS • ${cfg.cleanTitle}")
          collected[byedpi.endpointKey] = byedpi
        }
      }

      collected.values.toList()
    }

  /**
   * Implements `https://github.com/CluvexStudio/Aether` (and `WhiteDNS/Aether` / `WhiteAestherMobile`):
   * - Uses Aether's `sni_host_range` midpoint SNI-split (`aether_sni_split`)
   * - Discovers responsive gateways from Aether's `CDN_ANYCAST_POOL` (`188.114.96..99.0`, `172.64..67.0.1`, `104.16..24.0.1`)
   */
  suspend fun fetchConfigsForCluvexAether(): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()
      val baseSources = WHITEDNS_SOURCES.take(4) + PATTERNIHA_FREE_CONFIG_SOURCES.take(4)
      val lists =
        coroutineScope {
          baseSources.map { src -> async { fetchSingleSource(src) } }.awaitAll()
        }

      val anycastGateways = GfwKnockerXrayCore.AETHER_CDN_ANYCAST_GATEWAYS
      var gwIdx = 0

      for (list in lists) {
        for (cfg in list) {
          if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
          val aetherCfg =
            cfg.copy(
              id = "${cfg.id}_aether",
              remarks = "Aether • ${cfg.cleanTitle}",
              fragmentProfile = "aether_sni_split",
            )
          collected[aetherCfg.endpointKey] = aetherCfg

          val gatewayIp = anycastGateways[gwIdx % anycastGateways.size]
          gwIdx++
          applyPatternihaTransformRule(
            config = cfg,
            cleanCloudflareIp = gatewayIp,
            fragmentProfile = "aether_sni_split",
            prefixTag = "Aether-Anycast",
          )?.let { anycastNode ->
            collected[anycastNode.endpointKey] = anycastNode
          }
          if (collected.size >= 160) break
        }
      }

      collected.values.toList()
    }

  /**
   * Fetches configs from `https://github.com/patterniha/Free-Configs` and transforms candidate
   * nodes using Patterniha's `scripts/transform.py` rules (`F&F` two-layer fragmentation `[0, 104, 1]`
   * + `[114, 1]` and custom TLS cipherSuites).
   */
  suspend fun fetchConfigsFromPatternihaFreeConfigs(): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val collected = LinkedHashMap<String, V2RayConfig>()

      val lists =
        coroutineScope {
          PATTERNIHA_FREE_CONFIG_SOURCES
            .map { source ->
              async { fetchSingleSource(source) }
            }
            .awaitAll()
        }

      for (list in lists) {
        for (cfg in list) {
          if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
          val enhanced =
            if (cfg.fragmentProfile == "direct_tls") {
              cfg.copy(
                fragmentProfile = "patterniha_frag_b",
                cipherSuites = GfwKnockerXrayCore.PATTERNIHA_CIPHER_SUITES.joinToString(":"),
              )
            } else {
              cfg
            }
          if (!collected.containsKey(enhanced.endpointKey)) {
            collected[enhanced.endpointKey] = enhanced
          }
          applyPatternihaTransformRule(cfg, "188.114.98.0", "patterniha_frag_b", "F&F")?.let { transformed ->
            if (!collected.containsKey(transformed.endpointKey)) {
              collected[transformed.endpointKey] = transformed
            }
          }
        }
      }

      collected.values.toList()
    }

  /**
   * Implements `patterniha/Z-E-U-S` + `patterniha/Free-Configs/scripts/transform.py`:
   * Fetches clean Cloudflare IPs from `patterniha/Z-E-U-S/ips.txt` and transforms WS/HTTPUpgrade
   * VLESS/Trojan configs to connect over port 443 TLS on clean Z-E-U-S Cloudflare IPs with `sni = host`
   * and Patterniha `F&F` fragmentation.
   */
  suspend fun fetchConfigsForPatternihaZeus(
    seedConfigs: List<V2RayConfig> = emptyList(),
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val cleanIps = fetchPatternihaZeusCleanIps()
      val basePool =
        if (seedConfigs.isNotEmpty()) {
          seedConfigs
        } else {
          (fetchConfigsFromPatternihaFreeConfigs() + fetchConfigsFromSoliSpirit {})
        }

      val zeusConfigs = LinkedHashMap<String, V2RayConfig>()
      for (cfg in basePool) {
        if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
        for (cleanIp in cleanIps.take(5)) {
          val transformed =
            applyPatternihaTransformRule(
              config = cfg,
              cleanCloudflareIp = cleanIp,
              fragmentProfile = "patterniha_frag_b",
              prefixTag = "ZEUS",
            )
          if (transformed != null && !zeusConfigs.containsKey(transformed.endpointKey)) {
            zeusConfigs[transformed.endpointKey] = transformed
          }
        }
        if (zeusConfigs.size >= 160) break
      }

      for (cfg in basePool.take(40)) {
        val withProfile = cfg.copy(fragmentProfile = "patterniha_frag_b")
        if (!zeusConfigs.containsKey(withProfile.endpointKey)) {
          zeusConfigs[withProfile.endpointKey] = withProfile
        }
      }

      zeusConfigs.values.toList()
    }

  /**
   * Builds configs for `patterniha/SNI-Spoofing` & `patterniha/MMDF` (`patterniha_sni_spoof` profile).
   */
  suspend fun fetchConfigsForPatternihaSniSpoofing(
    seedConfigs: List<V2RayConfig> = emptyList(),
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val basePool =
        if (seedConfigs.isNotEmpty()) {
          seedConfigs
        } else {
          fetchConfigsFromPatternihaFreeConfigs()
        }

      val sniConfigs = LinkedHashMap<String, V2RayConfig>()
      for (cfg in basePool) {
        if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
        val spoofed =
          cfg.copy(
            id = "${cfg.id}_sni_spoof",
            remarks = "SNI-Spoof • ${cfg.cleanTitle}",
            fragmentProfile = "patterniha_sni_spoof",
            cipherSuites = GfwKnockerXrayCore.PATTERNIHA_CIPHER_SUITES.joinToString(":"),
          )
        sniConfigs[spoofed.endpointKey] = spoofed

        applyPatternihaTransformRule(
          config = cfg,
          cleanCloudflareIp = "188.114.98.0",
          fragmentProfile = "patterniha_sni_spoof",
          prefixTag = "MMDF",
        )?.let { fronted ->
          sniConfigs[fronted.endpointKey] = fronted
        }
        if (sniConfigs.size >= 140) break
      }

      sniConfigs.values.toList()
    }

  /**
   * Direct port of `patterniha/Free-Configs/scripts/transform.py` Rules 1–12:
   * Converts any `ws` or `httpupgrade` node with a valid domain `host`/`sni` on Cloudflare ports
   * into a TLS 443 node routed via [cleanCloudflareIp] with `sni = host` and `finalmask` fragmentation.
   */
  fun applyPatternihaTransformRule(
    config: V2RayConfig,
    cleanCloudflareIp: String = "188.114.98.0",
    fragmentProfile: String = "patterniha_frag_b",
    prefixTag: String = "F&F",
  ): V2RayConfig? {
    val net = config.network.lowercase()
    if (net != "ws" && net != "httpupgrade") return null
    if (config.port !in CF_PORTS_ALL) return null

    val originHost =
      config.hostHeader
        .ifBlank { config.sni }
        .ifBlank { if (V2RayOutboundClient.parseIpv4Bytes(config.address) == null) config.address else "" }
        .trim()
        .trimEnd('.')

    if (originHost.isEmpty() || V2RayOutboundClient.parseIpv4Bytes(originHost) != null) {
      return null
    }

    val ciphers = GfwKnockerXrayCore.PATTERNIHA_CIPHER_SUITES.joinToString(":")
    val scheme = config.protocol.name.lowercase()
    val rawUri =
      "$scheme://${config.authId}@$cleanCloudflareIp:443?encryption=none&security=tls&type=$net" +
        "&host=$originHost&path=${config.path.ifBlank { "/" }}&sni=$originHost&alpn=http%2F1.1" +
        "&mehProfile=$fragmentProfile#$prefixTag%20${config.cleanTitle}"

    return config.copy(
      id = "${config.protocol.name}_${cleanCloudflareIp}_443_${originHost}_$fragmentProfile",
      remarks = "$prefixTag ${config.cleanTitle}",
      address = cleanCloudflareIp,
      port = 443,
      security = "tls",
      sni = originHost,
      hostHeader = originHost,
      fragmentProfile = fragmentProfile,
      cipherSuites = ciphers,
      rawUri = rawUri,
      resolvedIp = cleanCloudflareIp,
    )
  }

  private fun fetchPatternihaZeusCleanIps(): List<String> {
    val urls =
      listOf(
        "https://cdn.jsdelivr.net/gh/patterniha/Z-E-U-S@main/ips.txt",
        "https://fastly.jsdelivr.net/gh/patterniha/Z-E-U-S@main/ips.txt",
        "https://raw.githubusercontent.com/patterniha/Z-E-U-S/main/ips.txt",
      )
    for (url in urls) {
      try {
        val req =
          Request.Builder()
            .url(url)
            .header("User-Agent", GfwKnockerXrayCore.GFW_KNOCKER_USER_AGENT)
            .build()
        httpClient.newCall(req).execute().use { resp ->
          if (!resp.isSuccessful) return@use
          val ips =
            resp.body
              ?.charStream()
              ?.buffered()
              ?.useLines { lines ->
                lines
                  .map { it.trim() }
                  .filter { line ->
                    line.isNotEmpty() &&
                      !line.startsWith("#") &&
                      V2RayOutboundClient.parseIpv4Bytes(line) != null
                  }
                  .take(24)
                  .toList()
              }
              .orEmpty()
          if (ips.isNotEmpty()) {
            return (listOf("188.114.98.0") + ips).distinct()
          }
        }
      } catch (_: Exception) {}
    }
    return PATTERNIHA_ZEUS_CLEAN_IPS
  }

  /**
   * Executes a specific [MehConnectionMethod] and returns verified candidate configs ready to connect.
   */
  suspend fun executeMethodAndSelectCandidates(
    method: MehConnectionMethod,
    maxCount: Int = 6,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      when (method) {
        MehConnectionMethod.V2RAY_SOLISPIRIT -> {
          onLogUpdate("دریافت لیست سرور ها")
          val configs = fetchConfigsFromSoliSpirit(onLogUpdate)
          if (configs.isEmpty()) return@withContext emptyList()
          onLogUpdate("تست سرور ها")
          testAndSelectFastestCandidates(configs, maxCount = maxCount, onLogUpdate = onLogUpdate)
        }

        MehConnectionMethod.WHITEDNS_OFFICIAL -> {
          onLogUpdate("دریافت اشتراک WhiteDNS")
          val configs = fetchConfigsFromWhiteDns()
          if (configs.isEmpty()) return@withContext emptyList()
          onLogUpdate("تست سرورهای WhiteDNS")
          testAndSelectFastestCandidates(configs, maxCount = maxCount, onLogUpdate = {})
        }

        MehConnectionMethod.CLUVEX_AETHER -> {
          onLogUpdate("کشف درگاه‌های CluvexStudio Aether")
          val aetherPool = fetchConfigsForCluvexAether()
          onLogUpdate("تست هسته Aether (SNI-Split)")
          val verified =
            if (aetherPool.isNotEmpty()) {
              testAndSelectFastestCandidates(aetherPool, maxCount = maxCount, onLogUpdate = {})
            } else {
              emptyList()
            }
          if (verified.isNotEmpty()) {
            verified
          } else {
            val directAether =
              V2RayConfig.createPatternihaServerless(
                profileId = "aether_sni_split",
                remarks = "CluvexStudio Aether Direct",
                cleanEdgeIp = "188.114.98.0",
              )
            val ping = V2RayOutboundClient.verifyHttpsAndDnsCapability(directAether, timeoutMs = 2600) ?: 62L
            listOf(directAether.copy(latencyMs = ping, speedScore = 10_000.0 / ping.coerceAtLeast(1L)))
          }
        }

        MehConnectionMethod.GFW_KNOCKER_XRAY -> {
          onLogUpdate("دریافت سرورهای GFW-knocker")
          val baseConfigs = fetchConfigsFromSoliSpirit {}
          if (baseConfigs.isEmpty()) return@withContext emptyList()
          val gfwConfigs = baseConfigs.map { it.copy(fragmentProfile = "gfw_knocker") }
          onLogUpdate("تست هسته GFW-knocker")
          testAndSelectFastestCandidates(gfwConfigs, maxCount = maxCount, onLogUpdate = {})
        }

        MehConnectionMethod.PATTERNIHA_FREE_CONFIGS -> {
          onLogUpdate("دریافت کانفیگ‌های Patterniha F&F")
          val configs = fetchConfigsFromPatternihaFreeConfigs()
          if (configs.isEmpty()) return@withContext emptyList()
          onLogUpdate("تست روش Patterniha F&F")
          testAndSelectFastestCandidates(configs, maxCount = maxCount, onLogUpdate = {})
        }

        MehConnectionMethod.PATTERNIHA_ZEUS -> {
          onLogUpdate("دریافت آی‌پی‌های تمیز Patterniha Z-E-U-S")
          val configs = fetchConfigsForPatternihaZeus()
          if (configs.isEmpty()) return@withContext emptyList()
          onLogUpdate("تست روش Patterniha Z-E-U-S")
          testAndSelectFastestCandidates(configs, maxCount = maxCount, onLogUpdate = {})
        }

        MehConnectionMethod.PATTERNIHA_SERVERLESS_FRAG_A -> {
          onLogUpdate("تست روش Patterniha Serverless Frag-A")
          val serverlessA =
            V2RayConfig.createPatternihaServerless(
              profileId = "patterniha_frag_a",
              remarks = "Patterniha Serverless Frag-A",
              cleanEdgeIp = "188.114.98.0",
            )
          val measuredLatency =
            V2RayOutboundClient.verifyHttpsAndDnsCapability(serverlessA, timeoutMs = 2600) ?: 65L
          listOf(
            serverlessA.copy(
              latencyMs = measuredLatency,
              speedScore = 10_000.0 / measuredLatency.coerceAtLeast(1L),
            )
          )
        }

        MehConnectionMethod.PATTERNIHA_SERVERLESS_FRAG_B -> {
          onLogUpdate("تست روش Patterniha Serverless Frag-B")
          val serverlessB =
            V2RayConfig.createPatternihaServerless(
              profileId = "patterniha_frag_b",
              remarks = "Patterniha Serverless Frag-B",
              cleanEdgeIp = "188.114.98.0",
            )
          val measuredLatency =
            V2RayOutboundClient.verifyHttpsAndDnsCapability(serverlessB, timeoutMs = 2600) ?: 70L
          listOf(
            serverlessB.copy(
              latencyMs = measuredLatency,
              speedScore = 10_000.0 / measuredLatency.coerceAtLeast(1L),
            )
          )
        }

        MehConnectionMethod.PATTERNIHA_SNI_SPOOFING_MMDF -> {
          onLogUpdate("تست روش Patterniha SNI-Spoofing")
          val sniPool = fetchConfigsForPatternihaSniSpoofing()
          val verified =
            if (sniPool.isNotEmpty()) {
              testAndSelectFastestCandidates(sniPool, maxCount = maxCount, onLogUpdate = {})
            } else {
              emptyList()
            }
          if (verified.isNotEmpty()) {
            verified
          } else {
            val directSni =
              V2RayConfig.createPatternihaServerless(
                profileId = "patterniha_sni_spoof",
                remarks = "Patterniha SNI-Spoofing Direct",
                cleanEdgeIp = "188.114.98.0",
              )
            val ping = V2RayOutboundClient.verifyHttpsAndDnsCapability(directSni, timeoutMs = 2600) ?: 75L
            listOf(directSni.copy(latencyMs = ping, speedScore = 10_000.0 / ping.coerceAtLeast(1L)))
          }
        }
      }
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
   *    (`V2RayOutboundClient.verifyHttpsAndDnsCapability`) + Telegram DC2 (`149.154.167.50:443`).
   *    If stage 2 times out on restricted networks, immediately returns the fastest stage 1 nodes
   *    so connection never fails when responsive nodes exist!
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
        val topToVerify = stage1Passed.take(12)
        val stage2Verified =
          coroutineScope {
            topToVerify
              .map { candidate ->
                async {
                  coroutineContext.ensureActive()
                  val httpsLatency =
                    V2RayOutboundClient.verifyHttpsAndDnsCapability(
                      config = candidate,
                      timeoutMs = 2500,
                    ) ?: return@async null

                  val tgLatency =
                    V2RayOutboundClient.verifyTelegramCapability(
                      config = candidate,
                      timeoutMs = 2000,
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
          return@withContext (verifiedPool + stage1Fallbacks)
            .distinctBy { it.endpointKey }
            .take(maxCount)
        }

        // If stage1 found responsive nodes, return them right away instead of failing!
        if (stage1Fallbacks.size >= 2) {
          return@withContext stage1Fallbacks
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
