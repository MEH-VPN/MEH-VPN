package com.meh.vpn.data

import com.meh.vpn.model.GitHubSubscriptionSource
import com.meh.vpn.model.V2RayConfig
import com.meh.vpn.model.V2RayProtocol
import com.meh.vpn.vpn.V2RayOutboundClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlin.system.measureTimeMillis

class GitHubSubscriptionAggregator {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(2500, TimeUnit.MILLISECONDS)
        .readTimeout(3000, TimeUnit.MILLISECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    fun cancelAllRequests() {
        runCatching { httpClient.dispatcher.cancelAll() }
    }

    val defaultGitHubSources = listOf(
        GitHubSubscriptionSource(
            id = "solispirit",
            repoName = "SoliSpirit/v2ray-configs",
            repoUrl = "https://github.com/SoliSpirit/v2ray-configs",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/Protocols/vless.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mohammadbahemmat",
            repoName = "MohammadBahemmat/V2ray-Collector",
            repoUrl = "https://github.com/MohammadBahemmat/V2ray-Collector",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/MohammadBahemmat/V2ray-Collector@main/vless.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/vless.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "barry_far",
            repoName = "barry-far/V2ray-Configs",
            repoUrl = "https://github.com/barry-far/V2ray-Configs",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Configs@main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "epodonios",
            repoName = "Epodonios/v2ray-configs",
            repoUrl = "https://github.com/Epodonios/v2ray-configs",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mahdibland",
            repoName = "mahdibland/V2RayAggregator",
            repoUrl = "https://github.com/mahdibland/V2RayAggregator",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/mahdibland/V2RayAggregator@master/sub/splitted/vless.txt",
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "yebekhe_tvc",
            repoName = "yebekhe/TVC",
            repoUrl = "https://github.com/yebekhe/TVC",
            candidateRawUrls = listOf(
                "https://cdn.jsdelivr.net/gh/yebekhe/TVC@main/subscriptions/xray/normal/vless",
                "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
                "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix"
            )
        )
    )

    /**
     * Fetches V2Ray configs from all configured GitHub repositories concurrently,
     * prioritizing tunnel-compatible VLESS and Trojan nodes (TCP/WS/TLS) and reporting live progress.
     */
    suspend fun fetchAllGitHubConfigs(
        sources: List<GitHubSubscriptionSource> = defaultGitHubSources,
        maxNodesPerSource: Int = 30,
        onSourceProgress: ((completedSources: Int, totalSources: Int, totalFound: Int) -> Unit)? = null
    ): List<V2RayConfig> = withContext(Dispatchers.IO) {
        coroutineScope {
            val activeSources = sources.filter { it.isEnabled }
            val completedCounter = java.util.concurrent.atomic.AtomicInteger(0)
            val discoveredCounter = java.util.concurrent.atomic.AtomicInteger(0)

            val fetchedLists = activeSources.map { source ->
                async {
                    val list = fetchConfigsFromSource(source, maxNodesPerSource)
                    val done = completedCounter.incrementAndGet()
                    val totalNow = discoveredCounter.addAndGet(list.size)
                    onSourceProgress?.invoke(done, activeSources.size, totalNow)
                    list
                }
            }.awaitAll()

            val mergedMap = LinkedHashMap<String, V2RayConfig>()
            fetchedLists.forEach { list ->
                list.forEach { cfg ->
                    if (isDirectTunnelSupported(cfg)) {
                        val key = "${cfg.protocol}:${cfg.address.lowercase()}:${cfg.port}:${cfg.uuidOrPassword}"
                        if (!mergedMap.containsKey(key)) {
                            mergedMap[key] = cfg
                        }
                    }
                }
            }

            mergedMap.values.take(90)
        }
    }

    private fun isDirectTunnelSupported(cfg: V2RayConfig): Boolean {
        val protoOk = cfg.protocol == V2RayProtocol.VLESS || cfg.protocol == V2RayProtocol.TROJAN
        val net = cfg.network.lowercase()
        val netOk = net == "tcp" || net == "ws" || net == "httpupgrade"
        val tlsOk = !cfg.tls.equals("reality", ignoreCase = true)
        return protoOk && netOk && tlsOk
    }

    private fun fetchConfigsFromSource(
        source: GitHubSubscriptionSource,
        maxNodes: Int
    ): List<V2RayConfig> {
        for (rawUrl in source.candidateRawUrls) {
            val body = fetchUrlText(rawUrl)
            if (body.isNotEmpty()) {
                val parsed = V2RayParser.parseSubscriptionPayload(
                    payload = body,
                    sourceRepo = source.repoName,
                    maxLimit = maxNodes,
                    filterPredicate = ::isDirectTunnelSupported
                )
                if (parsed.isNotEmpty()) {
                    return parsed
                }
            }
        }
        return emptyList()
    }

    /**
     * Quickly pre-filters [configs] by TCP handshake latency and returns up to [maxCandidates]
     * lowest-latency reachable servers.
     */
    suspend fun rankTopTcpCandidates(
        configs: List<V2RayConfig>,
        maxCandidates: Int = 10,
        timeoutMs: Int = 700
    ): List<V2RayConfig> = withContext(Dispatchers.IO) {
        if (configs.isEmpty()) return@withContext emptyList()

        val candidatePool = configs.filterNot { V2RayOutboundClient.isNodeBlacklisted(it) }
            .ifEmpty { configs }

        val tcpSemaphore = Semaphore(32)
        val tcpTested = coroutineScope {
            candidatePool.map { config ->
                async {
                    tcpSemaphore.withPermit {
                        val tcpPing = measureTcpHandshakeMs(config.address, config.port, timeoutMs)
                        config.copy(pingMs = tcpPing)
                    }
                }
            }.awaitAll()
        }

        tcpTested
            .filter { it.isReachable }
            // Prioritize European Tier-1 nodes (DE, NL, FI, FR, GB, SE, CH) ahead of TR transit relays on MCI
            .sortedWith(
                compareBy<V2RayConfig> { it.countryCode.equals("TR", ignoreCase = true) }
                    .thenBy { it.pingMs }
            )
            .take(maxCandidates)
    }

    /**
     * Two-stage smart server verification with bounded test count (max 12 V2Ray candidates)
     * and early-exit as soon as a verified open-internet server is found.
     */
    suspend fun findFastestServer(
        configs: List<V2RayConfig>,
        timeoutMs: Int = 700
    ): Pair<V2RayConfig?, List<V2RayConfig>> = withContext(Dispatchers.IO) {
        val topCandidates = rankTopTcpCandidates(configs, maxCandidates = 10, timeoutMs = timeoutMs)
        if (topCandidates.isEmpty()) {
            return@withContext null to emptyList()
        }

        val workingServers = mutableListOf<V2RayConfig>()
        // Test in fast batches of 4 so we connect immediately when the first working server responds
        for (batch in topCandidates.chunked(4)) {
            val verifiedBatch = coroutineScope {
                batch.map { candidate ->
                    async {
                        val realHttpPing = V2RayOutboundClient.verifyRealInternetConnectivity(
                            config = candidate,
                            vpnService = null,
                            timeoutMs = 2200
                        )
                        candidate.copy(pingMs = realHttpPing)
                    }
                }.awaitAll()
            }.filter { it.isReachable }.sortedBy { it.pingMs }

            if (verifiedBatch.isNotEmpty()) {
                workingServers.addAll(verifiedBatch)
                return@withContext workingServers.first() to workingServers
            }
        }

        return@withContext null to emptyList()
    }

    fun measureTcpHandshakeMs(host: String, port: Int, timeoutMs: Int = 900): Int {
        return try {
            val duration = measureTimeMillis {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(host, port), timeoutMs)
                }
            }
            duration.toInt().coerceAtLeast(1)
        } catch (_: Exception) {
            Int.MAX_VALUE
        }
    }

    private fun fetchUrlText(url: String): String {
        return try {
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "MEH-Android/1.0")
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return ""
                response.body?.string().orEmpty()
            }
        } catch (_: Exception) {
            ""
        }
    }
}
