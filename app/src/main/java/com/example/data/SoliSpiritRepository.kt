package com.example.data

import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.model.V2RayProtocol
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
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VMess-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/vmess.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/SS-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/shadowsocks.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/all_base64.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/AllSub-CDN",
          url = "https://cdn.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/all.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        // Batch 2: Fastly & GCore mirrors for rzashakeri/v2ray-configs
        SubscriptionSource(
          name = "RzaShakeri/VLESS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VMess-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/vmess.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/SS-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/shadowsocks.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-Fastly",
          url = "https://fastly.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/all_base64.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VLESS-GCore",
          url = "https://gcore.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        // Batch 3: Raw GitHub & root file endpoints for rzashakeri/v2ray-configs
        SubscriptionSource(
          name = "RzaShakeri/Trojan-GCore",
          url = "https://gcore.jsdelivr.net/gh/rzashakeri/v2ray-configs@main/configs/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VLESS-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/vless.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Trojan-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/trojan.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/VMess-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/vmess.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/SS-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/shadowsocks.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/Sub1-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/all_base64.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
        SubscriptionSource(
          name = "RzaShakeri/AllSub-Raw",
          url = "https://raw.githubusercontent.com/rzashakeri/v2ray-configs/main/configs/all.txt",
          repoLabel = "rzashakeri/v2ray-configs",
        ),
      )

    /**
     * Tier 2 subscription sources (mhcfpTopic/config). Fetched only when Priority #1
     * (rzashakeri/v2ray-configs) yields no working server.
     */
    val MHCFP_SOURCES =
      listOf(
        SubscriptionSource(
          name = "MhcfpTopic/XrayFinal-CDN",
          url = "https://cdn.jsdelivr.net/gh/mhcfpTopic/config@main/xray_final.txt",
          repoLabel = "mhcfpTopic/config",
        ),
        SubscriptionSource(
          name = "MhcfpTopic/XrayFinal-Raw",
          url = "https://raw.githubusercontent.com/mhcfpTopic/config/main/xray_final.txt",
          repoLabel = "mhcfpTopic/config",
        ),
      )
    val FALLBACK_SOURCES =
      listOf(
                // Batch 1: Fresh third-party subscriptions (added 2026-11-07 at the user's request).
        // The PSG page (itsyebekhe.github.io/PSG/) is an HTML generator, not a subscription file,
        // so the app fetches its underlying subscription file config.txt from the PSG repo.
        SubscriptionSource(
          name = "PSG/Config-CDN",
          url = "https://cdn.jsdelivr.net/gh/itsyebekhe/PSG@main/config.txt",
          repoLabel = "itsyebekhe/PSG",
        ),
        // Patterniha Free-Configs: 15 tested vless configs (3 nodes x variants).
        // Parser already handles its SNI-Spoofing/frag variants natively.
        SubscriptionSource(
          name = "Patterniha/FreeConfigs-CDN",
          url = "https://cdn.jsdelivr.net/gh/patterniha/Free-Configs@main/configs.txt",
          repoLabel = "patterniha/Free-Configs",
          ),
        // Community subscriptions added 2026-11-07 (vetted: small/tested lists first, giants last).
        SubscriptionSource(
            name = "F0rc3Run/VLESS-CDN",
          url = "https://cdn.jsdelivr.net/gh/F0rc3Run/F0rc3Run@main/splitted-by-protocol/vless.txt",
          repoLabel = "F0rc3Run/F0rc3Run",
          ),
    SubscriptionSource(
        name = "EmptyMouse/Sync",
      url = "https://empty-mouse-fbb7.alizareh4024.workers.dev/sync?sub=%D8%B3%D9%88%D8%B3%D9%85%D8%A7%D8%B1%F0%9F%A6%8E",
      repoLabel = "alizareh4024/workers",
      ),
    SubscriptionSource(
        name = "ThomasJasper/Sublist1-CDN",
      url = "https://cdn.jsdelivr.net/gh/ThomasJasperthecat/sub@main/sublist1.txt",
      repoLabel = "ThomasJasperthecat/sub",
      ),
    SubscriptionSource(
        name = "Pawdroid/FreeServers-CDN",
      url = "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
      repoLabel = "Pawdroid/Free-servers",
      ),
    SubscriptionSource(
        name = "Igareck/VLESS-Reality-Mobile-CDN",
      url = "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/Vless-Reality-White-Lists-Rus-Mobile.txt",
      repoLabel = "igareck/vpn-configs-for-russia",
      ),
    SubscriptionSource(
        name = "Igareck/BLACK-VLESS-RUS-CDN",
      url = "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/BLACK_VLESS_RUS.txt",
      repoLabel = "igareck/vpn-configs-for-russia",
      ),
    SubscriptionSource(
        name = "Igareck/BLACK-VLESS-RUS-Mobile-CDN",
      url = "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/BLACK_VLESS_RUS_mobile.txt",
      repoLabel = "igareck/vpn-configs-for-russia",
      ),
    SubscriptionSource(
        name = "Igareck/BLACK-SS-All-RUS-CDN",
      url = "https://cdn.jsdelivr.net/gh/igareck/vpn-configs-for-russia@main/BLACK_SS+All_RUS.txt",
      repoLabel = "igareck/vpn-configs-for-russia",
      ),
    SubscriptionSource(
        name = "ShadowException/VPNcat-CDN",
      url = "https://cdn.jsdelivr.net/gh/ShadowException/VPN@main/configs/VPN-cat",
      repoLabel = "ShadowException/VPN",
      ),
    SubscriptionSource(
        name = "Iampedi5/Base64",
      url = "https://sub.iampedi5.live/sub/base64.txt",
      repoLabel = "iampedi5/live",
      ),
    SubscriptionSource(
        name = "Pytimusprime/AllServers-CDN",
      url = "https://cdn.jsdelivr.net/gh/pytimusprime/FreeV2ray@main/all_servers.txt",
      repoLabel = "pytimusprime/FreeV2ray",
      ),
    SubscriptionSource(
        name = "Arshiacomplus/Sub-CDN",
      url = "https://cdn.jsdelivr.net/gh/arshiacomplus/v2rayExtractor@main/mix/sub.html",
      repoLabel = "arshiacomplus/v2rayExtractor",
      ),
    SubscriptionSource(
        name = "Ermaozi/V2Ray-CDN",
      url = "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt",
      repoLabel = "ermaozi/get_subscribe",
      ),
    SubscriptionSource(
        name = "BarryFar/Sub1-CDN",
      url = "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Sub1.txt",
      repoLabel = "barry-far/V2ray-Config",
      ),
    SubscriptionSource(
        name = "BarryFar/Sub2-CDN",
      url = "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Sub2.txt",
      repoLabel = "barry-far/V2ray-Config",
      ),
    SubscriptionSource(
        name = "BarryFar/Sub3-CDN",
      url = "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Sub3.txt",
      repoLabel = "barry-far/V2ray-Config",
      ),
    SubscriptionSource(
        name = "ALIILAPRO/Sub-CDN",
      url = "https://cdn.jsdelivr.net/gh/ALIILAPRO/v2rayNG-Config@main/sub.txt",
      repoLabel = "ALIILAPRO/v2rayNG-Config",
      ),
    SubscriptionSource(
        name = "Mahdibland/SubMerge-CDN",
      url = "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/sub_merge.txt",
      repoLabel = "mahdibland/V2RayAggregator",
      ),
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
        // Batch 2: Trojan, VMess, SS & Fastly mirrors from both repositories
        SubscriptionSource(
          name = "Bahemmat/Trojan-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/trojan_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/VMess-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vmess.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "Bahemmat/VMess-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/vmess_servers.txt",
          repoLabel = "MohammadBahemmat/V2ray-Collector",
        ),
        SubscriptionSource(
          name = "SoliSpirit/SS-CDN",
          url = "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/ss.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "Bahemmat/SS-CDN",
          url = "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/servers/shadowsocks_servers.txt",
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
          name = "SoliSpirit/VMess-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vmess.txt",
          repoLabel = "SoliSpirit/v2ray-configs",
        ),
        SubscriptionSource(
          name = "SoliSpirit/SS-Raw",
          url = "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/ss.txt",
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
        SubscriptionSource(
          name = "PSG/Config-Raw",
          url = "https://raw.githubusercontent.com/itsyebekhe/PSG/refs/heads/main/config.txt",
          repoLabel = "itsyebekhe/PSG",
        ),
        SubscriptionSource(
          name = "Patterniha/FreeConfigs-Raw",
          url = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
          repoLabel = "patterniha/Free-Configs",
          ),
        SubscriptionSource(
          name = "F0rc3Run/VLESS-Raw",
          url = "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
          repoLabel = "F0rc3Run/F0rc3Run",
        ),
        SubscriptionSource(
          name = "ThomasJasper/Sublist1-Raw",
          url = "https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
          repoLabel = "ThomasJasperthecat/sub",
        ),
        SubscriptionSource(
          name = "Pawdroid/FreeServers-Raw",
          url = "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
          repoLabel = "Pawdroid/Free-servers",
        ),
        SubscriptionSource(
          name = "Igareck/VLESS-Reality-Mobile-Raw",
          url = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
          repoLabel = "igareck/vpn-configs-for-russia",
        ),
        SubscriptionSource(
          name = "Igareck/BLACK-VLESS-RUS-Raw",
          url = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
          repoLabel = "igareck/vpn-configs-for-russia",
        ),
        SubscriptionSource(
          name = "Igareck/BLACK-VLESS-RUS-Mobile-Raw",
          url = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
          repoLabel = "igareck/vpn-configs-for-russia",
        ),
        SubscriptionSource(
          name = "Igareck/BLACK-SS-All-RUS-Raw",
          url = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
          repoLabel = "igareck/vpn-configs-for-russia",
        ),
        SubscriptionSource(
          name = "ShadowException/VPNcat-Raw",
          url = "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
          repoLabel = "ShadowException/VPN",
        ),
        SubscriptionSource(
          name = "Pytimusprime/AllServers-Raw",
          url = "https://raw.githubusercontent.com/pytimusprime/FreeV2ray/refs/heads/main/all_servers.txt",
          repoLabel = "pytimusprime/FreeV2ray",
        ),
        SubscriptionSource(
          name = "Arshiacomplus/Sub-Raw",
          url = "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
          repoLabel = "arshiacomplus/v2rayExtractor",
        ),
        SubscriptionSource(
          name = "Ermaozi/V2Ray-Raw",
          url = "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
          repoLabel = "ermaozi/get_subscribe",
        ),
        SubscriptionSource(
          name = "BarryFar/Sub1-Raw",
          url = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
          repoLabel = "barry-far/V2ray-config",
        ),
        SubscriptionSource(
          name = "BarryFar/Sub2-Raw",
          url = "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
          repoLabel = "barry-far/V2ray-Config",
        ),
        SubscriptionSource(
          name = "BarryFar/Sub3-Raw",
          url = "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub3.txt",
          repoLabel = "barry-far/V2ray-Config",
        ),
        SubscriptionSource(
          name = "ALIILAPRO/Sub-Raw",
          url = "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
          repoLabel = "ALIILAPRO/v2rayNG-Config",
        ),
        SubscriptionSource(
          name = "Mahdibland/SubMerge-Raw",
          url = "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
          repoLabel = "mahdibland/V2RayAggregator",
        ),
        SubscriptionSource(
          name = "MasirSefid/Sub-Raw",
          url = "https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
          repoLabel = "masir-sefid/Sub",
        ),
        SubscriptionSource(
          name = "MasirSefid/TelegramChannel-Raw",
          url = "https://raw.githubusercontent.com/masir-sefid/Sub/main/Telegram-Channel-@Masir_Sefid.txt",
          repoLabel = "masir-sefid/Sub",
        ),
      )

    /**
     * Combined list of all registered sources: `rzashakeri/v2ray-configs` (Priority #1),
     * `mhcfpTopic/config` (Priority #2), then `SoliSpirit/v2ray-configs` and
     * `MohammadBahemmat/V2ray-Collector`.
     */
    val SOLISPIRIT_SOURCES = PRIMARY_RZASHAKERI_SOURCES + MHCFP_SOURCES + FALLBACK_SOURCES

    private const val WAVE_SIZE = 80
    private const val CONCURRENT_TEST_LIMIT = 32
    // Fast-connect path only: more parallel probes + a shorter first-pass probe so the
    // user waits less. Background refinement keeps the low-cost defaults (concurrency 6).
    // Aggressive first-30s mode: 128 parallel probes in waves of 160, so the first
    // passing server is found sooner.
    private const val FAST_CONNECT_CONCURRENCY = 128
    private const val FAST_CONNECT_WAVE_SIZE = 160
    private const val FAST_CONNECT_PROBE_TIMEOUT_MS = 1500
    private const val MAX_CONFIGS_PER_SOURCE = 1000

    /** Round 5: scan at least this long before connecting. */
    const val BEST_SCAN_MIN_DURATION_MS: Long = 60_000L

    /** Round 5: a verified node faster than this ends the scan at once. */
    const val BEST_SCAN_EARLY_STOP_PING_MS: Long = 1000L

    /** Round 5: size of the verified pool the scan returns, fastest first. */
    const val BEST_SCAN_POOL_SIZE: Int = 5

    /** Round 5: stage-2 checks per wave, fastest stage-1 results first. */
    private const val BEST_SCAN_VERIFY_PER_WAVE = 12
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

  /**
   * Fetches configs from the tier-2 repository (mhcfpTopic/config) when Priority #1
   * yields no working server.
   */
  suspend fun fetchMhcfpConfigs(
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      onLogUpdate("اتصال به ساب mhcfp ...")
      val configs = fetchFromSourceList(MHCFP_SOURCES)
      if (configs.isNotEmpty()) {
        onLogUpdate("${configs.size} سرور از ساب mhcfp دریافت شد")
      }
      configs
    }

  /**
   * All configs from every tier (primary + mhcfp + fallback), deduplicated by endpoint.
   * Used by the background node refinement so it can keep testing the whole pool,
   * not just the Priority #1 repository.
   */
  suspend fun fetchAllTierConfigs(): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val merged = LinkedHashMap<String, V2RayConfig>()
      for (configs in listOf(
        fetchFromSourceList(PRIMARY_RZASHAKERI_SOURCES),
        fetchFromSourceList(MHCFP_SOURCES),
        fetchFromSourceList(FALLBACK_SOURCES),
      )) {
        for (cfg in configs) {
          if (!merged.containsKey(cfg.endpointKey)) {
            merged[cfg.endpointKey] = cfg
          }
        }
      }
      merged.values.toList()
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
            ?.useLines { lines -> lines.take(2000).joinToString("\n") }
            .orEmpty()
        V2RayConfigParser.parseSubscriptionContent(bodyText).take(MAX_CONFIGS_PER_SOURCE)
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
    maxWaves: Int = Int.MAX_VALUE,
    concurrency: Int = CONCURRENT_TEST_LIMIT,
    verifyConcurrency: Int = 6,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      // Hysteria2, TUIC and WireGuard are UDP-only and can never pass the TCP 204 probe,
      // so they must not occupy stage-1 wave slots.
      val testable: (V2RayConfig) -> Boolean = {
        V2RayOutboundClient.isSupportedByEngine(it) &&
          it.protocol != V2RayProtocol.HYSTERIA2 &&
          it.protocol != V2RayProtocol.TUIC &&
          it.protocol != V2RayProtocol.WIREGUARD
      }
      val validSaved = prioritizedSavedNodes.filter(testable)
      val savedKeys = validSaved.map { it.endpointKey }.toSet()
      val remainingSupported =
        configs
          .filter { testable(it) && it.endpointKey !in savedKeys }
          .shuffled()

      val supported = validSaved + remainingSupported
      if (supported.isEmpty()) return@withContext emptyList()

      val semaphore = Semaphore(concurrency.coerceAtLeast(1))
      val completedCount = AtomicInteger(0)
      val passedCount = AtomicInteger(0)

      onLogUpdate("شروع تست سرعت روی ${supported.size} سرور ...")

      val fullSocialPool = mutableListOf<V2RayConfig>()
      val partialSocialPool = mutableListOf<V2RayConfig>()
      val fallbackHttpsPool = mutableListOf<V2RayConfig>()
      val stage2Semaphore = Semaphore(verifyConcurrency.coerceAtLeast(1))

      // Default maxWaves is uncapped, so all fetched configs are tested wave by wave; callers needing a cap pass maxWaves explicitly.
      val waves = supported.chunked(WAVE_SIZE).take(maxWaves.coerceAtLeast(1))
      for ((waveIdx, wave) in waves.withIndex()) {
        coroutineContext.ensureActive()
        val stage1Passed =
          coroutineScope {
            wave
              .map { config ->
                async {
                  semaphore.withPermit {
                    coroutineContext.ensureActive()
                    val measured = measureNodeSpeed(config)
                    val done = completedCount.incrementAndGet()
                    if (measured != null) passedCount.incrementAndGet()
                    if (done % 20 == 0) {
                      onLogUpdate("تست سرور ها: $done/${wave.size} کامل شد، ${passedCount.get()} موفق")
                    }
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

        if (stage1Passed.isEmpty()) {
          onLogUpdate("موج ${waveIdx + 1}: هیچ سروری از تست عبور نکرد")
          continue
        }

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

  /**
   * Fast first connect with immediate failover pool:
   * Finds the first node that passes the stage-1 204 probe AND a quick HTTPS/TLS check
   * to serve as primary, plus up to [poolSize - 1] further stage-2 verified nodes
   * as backup candidates in the local proxy failover pool so the connection can instantly
   * survive packet loss or node drops before background refinement kicks in.
   */
  suspend fun findFastCandidatesWithFailoverPool(
    configs: List<V2RayConfig>,
    prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
    poolSize: Int = 4,
    concurrency: Int = FAST_CONNECT_CONCURRENCY,
    probeTimeoutMs: Int = FAST_CONNECT_PROBE_TIMEOUT_MS,
    waveSize: Int = WAVE_SIZE,
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
      val testable: (V2RayConfig) -> Boolean = {
        V2RayOutboundClient.isSupportedByEngine(it) &&
          it.protocol != V2RayProtocol.HYSTERIA2 &&
          it.protocol != V2RayProtocol.TUIC &&
          it.protocol != V2RayProtocol.WIREGUARD
      }
      val validSaved = prioritizedSavedNodes.filter(testable)
      val savedKeys = validSaved.map { it.endpointKey }.toSet()
      val remaining =
        configs
          .filter { testable(it) && it.endpointKey !in savedKeys }
          .shuffled()
      val supported = validSaved + remaining
      if (supported.isEmpty()) return@withContext emptyList()

      onLogUpdate("شروع تست سرعت روی ${supported.size} سرور ...")
      val semaphore = Semaphore(concurrency)
      for ((waveIdx, wave) in supported.chunked(waveSize).withIndex()) {
        coroutineContext.ensureActive()
        val stage1Passed =
          coroutineScope {
            wave
              .map { config ->
                async {
                  semaphore.withPermit {
                    coroutineContext.ensureActive()
                    measureNodeSpeed(config, timeoutMs = probeTimeoutMs)
                  }
                }
              }
              .awaitAll()
              .filterNotNull()
              .sortedBy { it.latencyMs }
          }
        if (stage1Passed.isEmpty()) {
          onLogUpdate("موج ${waveIdx + 1}: هیچ سروری از تست عبور نکرد")
          continue
        }
                // Fastest passers of this wave: quick TLS checks in parallel (not one by one),
        // the pool holds only stage-2 verified nodes, fastest first.
        val verifiedCandidates =
          coroutineScope {
            stage1Passed.take(poolSize)
              .map { candidate ->
                async {
                  val httpsLatency =
                    V2RayOutboundClient.verifyHttpsAndDnsCapability(
                      config = candidate,
                      timeoutMs = 3000,
                    )
                  if (httpsLatency != null) candidate else null
                }
              }
              .awaitAll()
              .filterNotNull()
          }
        if (verifiedCandidates.isNotEmpty()) {
          onLogUpdate("بهترین سرور انتخاب شد (پینگ ${verifiedCandidates.first().latencyMs}ms)")
          return@withContext verifiedCandidates
        }
        onLogUpdate("موج ${waveIdx + 1}: عبور از تست اولیه ولی تایید TLS نشد")
      }
      emptyList()
    }

  /**
   * Fast first connect: probes configs wave by wave (80 per wave, 64 concurrent, 1500 ms
   * first-pass probe) and returns
   * the first node that passes the stage-1 204 probe AND a quick HTTPS/TLS check, without
   * waiting for the rest of the wave or later waves. Saved healthy nodes are tried first.
   * The caller connects to the returned node immediately; the background refinement keeps
   * testing the remaining pool and upgrades later if a clearly better node appears.
   */
  suspend fun findFirstPassingCandidate(
    configs: List<V2RayConfig>,
    prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
    onLogUpdate: (String) -> Unit,
  ): V2RayConfig? =
    findFastCandidatesWithFailoverPool(
      configs = configs,
      prioritizedSavedNodes = prioritizedSavedNodes,
      poolSize = 1,
      onLogUpdate = onLogUpdate,
    ).firstOrNull()

  /**
   * Pipelined fast connect: fetches sources in batches of 4 and probes each batch the
   * moment it arrives, instead of downloading the whole tier first. Saved healthy nodes
   * are tested before any download and stay first in the pool; the search keeps going
   * until the pool holds [poolSize] verified nodes, or no batch yields a server.
   */
  suspend fun findFirstPassingFromSources(
    sources: List<SubscriptionSource>,
    prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
    poolSize: Int = 4,
    excludedEndpointKeys: Set<String> = emptySet(),
    onLogUpdate: (String) -> Unit,
  ): List<V2RayConfig> =
    withContext(ioDispatcher) {
        // Fill the pool: saved nodes stay first, but keep searching the tiers until it is full.
      val pool =
        findFastCandidatesWithFailoverPool(
          configs = prioritizedSavedNodes.filter { it.endpointKey !in excludedEndpointKeys },
          poolSize = poolSize,
          waveSize = FAST_CONNECT_WAVE_SIZE,
          onLogUpdate = onLogUpdate,
        ).toMutableList()
      val seenKeys = pool.map { it.endpointKey }.toMutableSet()

            // No per-tier test budget on the connect path: the search keeps going through
      // every batch until a server passes (or the sources run out). Stopping early
      // is what used to turn the circle red while untested servers remained.
      for ((batchIdx, batch) in sources.chunked(4).withIndex()) {
        if (pool.size >= poolSize) break
        coroutineContext.ensureActive()
        onLogUpdate("دریافت دسته ${batchIdx + 1} از ساب‌ها ...")
        val batchConfigs =
          coroutineScope {
            batch
              .map { source ->
                async { fetchSingleSource(source) }
              }
              .awaitAll()
          }.flatten()
            .filter { V2RayOutboundClient.isSupportedByEngine(it) }
            .distinctBy { it.endpointKey }
        .filter { it.endpointKey !in excludedEndpointKeys }
          if (batchConfigs.isEmpty()) continue
        onLogUpdate("${batchConfigs.size} سرور از دسته ${batchIdx + 1} دریافت شد")
        val found =
          findFastCandidatesWithFailoverPool(
            configs = batchConfigs,
            poolSize = poolSize,
            waveSize = FAST_CONNECT_WAVE_SIZE,
            onLogUpdate = onLogUpdate,
          )
        for (candidate in found) {
          if (pool.size >= poolSize) break
          if (seenKeys.add(candidate.endpointKey)) pool.add(candidate)
        }
      }
      pool
    }

/**
     * Ranks stage-2-verified nodes fastest first, deduplicated by endpoint. When
     * the same endpoint was verified more than once, the fastest measurement wins.
     */
    fun rankVerifiedByPing(
        verified: List<V2RayConfig>,
        poolSize: Int = BEST_SCAN_POOL_SIZE,
    ): List<V2RayConfig> =
        verified
            .sortedBy { it.latencyMs }
            .distinctBy { it.endpointKey }
            .take(poolSize.coerceAtLeast(1))

    /**
     * Round 5: best-server scan. Unlike [findFirstPassingFromSources], which connects
     * to the first server that passes, this scans at full fast-connect power
     * (128 concurrent probes, 160-node waves, 1500 ms stage-1 timeout) for at least
     * [minScanDurationMs] across ALL tiers, never stopping at the first tier that
     * yields a node, and returns the fastest verified nodes first.
     *
     * Saved working nodes are still tried first, inside the scan. A node counts as
     * verified only when it passes stage 1 (TCP probe, the node latency in
     * [V2RayConfig.latencyMs]) and stage 2 (the HTTPS/DNS capability check).
     * Shadowsocks nodes stay excluded through [V2RayOutboundClient.isSupportedByEngine].
     *
     * The scan stops early only when a verified node is faster than [earlyStopPingMs].
     * After [minScanDurationMs] it returns the best verified nodes found so far; when
     * nothing has passed by then it keeps scanning the remaining tiers until something
     * passes (never give up). When every tier is exhausted without a single verified
     * node, the empty list is returned and the caller reports the failure as before.
     *
     * Live progress (tested count, verified count, best ping so far) is reported
     * through [onLogUpdate] so the screen never looks stuck on the testing phase.
     * Cancellation is honoured the same way as the rest of the pipeline, so
     * disconnect/cancel during connect still works.
     */
    suspend fun scanBestCandidatesAcrossAllTiers(
        prioritizedSavedNodes: List<V2RayConfig> = emptyList(),
        poolSize: Int = BEST_SCAN_POOL_SIZE,
        minScanDurationMs: Long = BEST_SCAN_MIN_DURATION_MS,
        earlyStopPingMs: Long = BEST_SCAN_EARLY_STOP_PING_MS,
        excludedEndpointKeys: Set<String> = emptySet(),
        onLogUpdate: (String) -> Unit,
    ): List<V2RayConfig> = withContext(ioDispatcher) {
        val scanStartedAt = System.currentTimeMillis()
        val verified = mutableListOf<V2RayConfig>()
        var testedCount = 0
        var lastProgressLogAt = 0L

        fun elapsedMs(): Long = System.currentTimeMillis() - scanStartedAt

        fun bestPingMs(): Long? = verified.minOfOrNull { it.latencyMs }

        fun logProgress(force: Boolean) {
            val now = elapsedMs()
            if (!force && now - lastProgressLogAt < 2_000L) return
            lastProgressLogAt = now
            val best = bestPingMs()
            val bestText =
                if (best == null) "هنوز سروری تایید نشده"
                else "بهترین پینگ " + best + "ms"
            onLogUpdate(
                "تست سرور ها: " + testedCount + " تست شد، " + verified.size +
                    " تایید شد، " + bestText + " (" + (now / 1_000L) + "ث)",
            )
        }

        fun noteVerified(candidates: List<V2RayConfig>) {
            for (candidate in candidates) {
                if (candidate.endpointKey in excludedEndpointKeys) continue
                val existing = verified.firstOrNull { it.endpointKey == candidate.endpointKey }
                if (existing == null) {
                    verified.add(candidate)
                } else if (candidate.latencyMs < existing.latencyMs) {
                    verified.remove(existing)
                    verified.add(candidate)
                }
            }
            verified.sortBy { it.latencyMs }
        }

        fun deadlineReached(): Boolean =
            elapsedMs() >= minScanDurationMs && verified.isNotEmpty()

        fun earlyStopReached(): Boolean =
            bestPingMs()?.let { it < earlyStopPingMs } == true

        // Tests one chunk of configs in fast-connect waves. Returns true when the
        // scan must stop: early stop, or the minimum scan time is over and at
        // least one node already passed. Returns false to keep scanning.
        suspend fun scanConfigs(configs: List<V2RayConfig>): Boolean {
            val testable: (V2RayConfig) -> Boolean = {
                V2RayOutboundClient.isSupportedByEngine(it) &&
                    it.protocol != V2RayProtocol.HYSTERIA2 &&
                    it.protocol != V2RayProtocol.TUIC &&
                    it.protocol != V2RayProtocol.WIREGUARD
            }
            val supported = configs.filter(testable)
            val semaphore = Semaphore(FAST_CONNECT_CONCURRENCY)
            for (wave in supported.chunked(FAST_CONNECT_WAVE_SIZE)) {
                coroutineContext.ensureActive()
                if (deadlineReached()) return true
                val stageOnePassed =
                    coroutineScope {
                        wave
                            .map { config ->
                                async {
                                    semaphore.withPermit {
                                        coroutineContext.ensureActive()
                                        measureNodeSpeed(
                                            config,
                                            timeoutMs = FAST_CONNECT_PROBE_TIMEOUT_MS,
                                        )
                                    }
                                }
                            }
                            .awaitAll()
                            .filterNotNull()
                            .sortedBy { it.latencyMs }
                    }
                testedCount += wave.size
                logProgress(force = false)
                if (stageOnePassed.isEmpty()) continue
                // Fastest passers of this wave: quick TLS checks in parallel (not
                // one by one); only stage-2 verified nodes join the pool.
                val verifiedInWave =
                    coroutineScope {
                        stageOnePassed.take(BEST_SCAN_VERIFY_PER_WAVE)
                            .map { candidate ->
                                async {
                                    val httpsLatency =
                                        V2RayOutboundClient.verifyHttpsAndDnsCapability(
                                            config = candidate,
                                            timeoutMs = 3000,
                                        )
                                    if (httpsLatency != null) candidate else null
                                }
                            }
                            .awaitAll()
                            .filterNotNull()
                    }
                noteVerified(verifiedInWave)
                logProgress(force = verifiedInWave.isNotEmpty())
                if (earlyStopReached()) {
                    onLogUpdate(
                        "سرور سریع پیدا شد (پینگ " + (bestPingMs() ?: 0L) +
                            "ms) — اتصال فوری",
                    )
                    return true
                }
                if (deadlineReached()) return true
            }
            return deadlineReached()
        }

        onLogUpdate("شروع اسکن بهترین سرور: حداقل 60 ثانیه بررسی همه مخزن‌ها")

        // Saved working nodes are tried first, inside the scan.
        val savedSupported =
            prioritizedSavedNodes.filter { V2RayOutboundClient.isSupportedByEngine(it) }
        if (savedSupported.isNotEmpty() && scanConfigs(savedSupported)) {
            return@withContext rankVerifiedByPing(verified, poolSize)
        }

        val tiers =
            listOf(
                "اولویت اول" to PRIMARY_RZASHAKERI_SOURCES,
                "اولویت دوم" to MHCFP_SOURCES,
                "اولویت سوم" to FALLBACK_SOURCES,
            )
        for ((tierLabel, tierSources) in tiers) {
            for ((batchIndex, batch) in tierSources.chunked(4).withIndex()) {
                coroutineContext.ensureActive()
                if (deadlineReached()) break
                logProgress(force = true)
                val batchConfigs =
                    coroutineScope {
                        batch
                            .map { source ->
                                async { fetchSingleSource(source) }
                            }
                            .awaitAll()
                    }.flatten()
                        .filter { V2RayOutboundClient.isSupportedByEngine(it) }
                        .distinctBy { it.endpointKey }
                        .filter { config ->
                            val verifiedKeys = verified.map { it.endpointKey }.toSet()
                            config.endpointKey !in excludedEndpointKeys &&
                                config.endpointKey !in verifiedKeys
                        }
                if (batchConfigs.isEmpty()) continue
                onLogUpdate(
                    "استخراج و بررسی اتصالات از مخزن " + tierLabel +
                        " (دسته " + (batchIndex + 1) + "، " + batchConfigs.size + " سرور)",
                )
                if (scanConfigs(batchConfigs)) break
            }
            if (deadlineReached() || earlyStopReached()) break
        }
        return@withContext rankVerifiedByPing(verified, poolSize)
    }

    fun measureNodeSpeed(
  config: V2RayConfig,
  timeoutMs: Int = 2600,
): V2RayConfig? {
    // UDP-only protocols can never pass the TCP 204 probe; skip them here as well
    // so background refine calls do not waste a probe slot on them either.
    if (config.protocol == V2RayProtocol.HYSTERIA2 ||
      config.protocol == V2RayProtocol.TUIC ||
      config.protocol == V2RayProtocol.WIREGUARD
    ) {
      return null
    }
    val resolvedIp = V2RayOutboundClient.resolveEndpointIpv4(config.address) ?: return null
    val withIp = config.copy(resolvedIp = resolvedIp)
    val realDelayMs = V2RayOutboundClient.measureRealProxyDelay(withIp, timeoutMs = timeoutMs) ?: return null
    val score = 10_000.0 / realDelayMs.toDouble()
    return withIp.copy(
      latencyMs = realDelayMs,
      speedScore = score,
    )
  }
}
