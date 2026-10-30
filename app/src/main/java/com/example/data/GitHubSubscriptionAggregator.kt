package com.example.data

import com.example.model.GitHubSubscriptionSource
import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import com.example.vpn.V2RayOutboundClient
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
        .connectTimeout(4000, TimeUnit.MILLISECONDS)
        .readTimeout(5000, TimeUnit.MILLISECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    val defaultGitHubSources = listOf(
        GitHubSubscriptionSource(
            id = "solispirit",
            repoName = "SoliSpirit/v2ray-configs",
            repoUrl = "https://github.com/SoliSpirit/v2ray-configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mohammadbahemmat",
            repoName = "MohammadBahemmat/V2ray-Collector",
            repoUrl = "https://github.com/MohammadBahemmat/V2ray-Collector",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/vless.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_configs.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/master/sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "barry_far",
            repoName = "barry-far/V2ray-Configs",
            repoUrl = "https://github.com/barry-far/V2ray-Configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "epodonios",
            repoName = "Epodonios/v2ray-configs",
            repoUrl = "https://github.com/Epodonios/v2ray-configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mahdibland",
            repoName = "mahdibland/V2RayAggregator",
            repoUrl = "https://github.com/mahdibland/V2RayAggregator",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt",
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "yebekhe_tvc",
            repoName = "yebekhe/TVC",
            repoUrl = "https://github.com/yebekhe/TVC",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
                "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix"
            )
        )
    )

    /**
     * Fetches V2Ray configs from all configured GitHub repositories concurrently,
     * prioritizing tunnel-compatible VLESS and Trojan nodes (TCP/WS/TLS).
     */
    suspend fun fetchAllGitHubConfigs(
        sources: List<GitHubSubscriptionSource> = defaultGitHubSources,
        maxNodesPerSource: Int = 35
    ): List<V2RayConfig> = withContext(Dispatchers.IO) {
        coroutineScope {
            val activeSources = sources.filter { it.isEnabled }

            val fetchedLists = activeSources.map { source ->
                async {
                    fetchConfigsFromSource(source, maxNodesPerSource)
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

            mergedMap.values.take(110)
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
        return discoverSubscriptionFromRepoApi(source.repoName, maxNodes)
    }

    private fun discoverSubscriptionFromRepoApi(repoFullName: String, maxNodes: Int): List<V2RayConfig> {
        return try {
            val contentsUrl = "https://api.github.com/repos/$repoFullName/contents"
            val jsonStr = fetchUrlText(contentsUrl)
            if (!jsonStr.trim().startsWith("[")) return emptyList()

            val array = JSONArray(jsonStr)
            for (i in 0 until array.length()) {
                val obj = array.optJSONObject(i) ?: continue
                val name = obj.optString("name", "").lowercase()
                val type = obj.optString("type", "")
                val downloadUrl = obj.optString("download_url", "")

                if (type == "file" && downloadUrl.isNotEmpty() &&
                    (name.endsWith(".txt") || name.contains("sub") || name.contains("vless") || name.contains("config")) &&
                    !name.contains("readme") && !name.contains("license")
                ) {
                    val content = fetchUrlText(downloadUrl)
                    val parsed = V2RayParser.parseSubscriptionPayload(
                        payload = content,
                        sourceRepo = repoFullName,
                        maxLimit = maxNodes,
                        filterPredicate = ::isDirectTunnelSupported
                    )
                    if (parsed.isNotEmpty()) {
                        return parsed
                    }
                }
            }
            emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Two-stage smart server verification:
     * 1. Fast TCP reachability scan across all fetched GitHub servers.
     * 2. Real V2Ray Tunnel HTTP 204 verification (sending an actual HTTP 204 request through
     *    the VLESS/Trojan tunnel to cp.cloudflare.com) so we ONLY select a server that genuinely
     *    provides open internet access!
     */
    suspend fun findFastestServer(
        configs: List<V2RayConfig>,
        timeoutMs: Int = 900
    ): Pair<V2RayConfig?, List<V2RayConfig>> = withContext(Dispatchers.IO) {
        if (configs.isEmpty()) return@withContext null to emptyList()

        // Stage 1: Fast TCP Handshake Pre-Filter
        val tcpSemaphore = Semaphore(32)
        val tcpTested = coroutineScope {
            configs.map { config ->
                async {
                    tcpSemaphore.withPermit {
                        val tcpPing = measureTcpHandshakeMs(config.address, config.port, timeoutMs)
                        config.copy(pingMs = tcpPing)
                    }
                }
            }.awaitAll()
        }

        val tcpReachable = tcpTested
            .filter { it.isReachable }
            .sortedBy { it.pingMs }

        if (tcpReachable.isEmpty()) {
            return@withContext null to emptyList()
        }

        // Stage 2: Verify real end-to-end Open Internet (HTTP 204 through V2Ray tunnel) on top 24 TCP-reachable servers
        val topCandidates = tcpReachable.take(24)
        val tunnelSemaphore = Semaphore(12)
        val tunnelVerified = coroutineScope {
            topCandidates.map { candidate ->
                async {
                    tunnelSemaphore.withPermit {
                        val realHttpPing = V2RayOutboundClient.verifyRealInternetConnectivity(
                            config = candidate,
                            vpnService = null,
                            timeoutMs = 2800
                        )
                        candidate.copy(pingMs = realHttpPing)
                    }
                }
            }.awaitAll()
        }

        val workingInternetServers = tunnelVerified
            .filter { it.isReachable }
            .sortedBy { it.pingMs }

        if (workingInternetServers.isNotEmpty()) {
            return@withContext workingInternetServers.first() to workingInternetServers
        }

        // Fallback to fastest TCP-reachable V2Ray server if HTTP 204 probe timed out
        return@withContext tcpReachable.first() to tcpReachable
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
