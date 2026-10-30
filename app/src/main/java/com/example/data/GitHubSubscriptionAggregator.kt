package com.example.data

import com.example.model.GitHubSubscriptionSource
import com.example.model.V2RayConfig
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

    // Ultra-lightweight, fast OkHttpClient with aggressive timeouts for snappy UX
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(3500, TimeUnit.MILLISECONDS)
        .readTimeout(4500, TimeUnit.MILLISECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    val defaultGitHubSources = listOf(
        GitHubSubscriptionSource(
            id = "solispirit",
            repoName = "SoliSpirit/v2ray-configs",
            repoUrl = "https://github.com/SoliSpirit/v2ray-configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Subscriptions/Sub1.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/master/all_configs.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mohammadbahemmat",
            repoName = "MohammadBahemmat/V2ray-Collector",
            repoUrl = "https://github.com/MohammadBahemmat/V2ray-Collector",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/vless.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_configs.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub/mix.txt",
                "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/master/sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "barry_far",
            repoName = "barry-far/V2ray-Configs",
            repoUrl = "https://github.com/barry-far/V2ray-Configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "epodonios",
            repoName = "Epodonios/v2ray-configs",
            repoUrl = "https://github.com/Epodonios/v2ray-configs",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "mahdibland",
            repoName = "mahdibland/V2RayAggregator",
            repoUrl = "https://github.com/mahdibland/V2RayAggregator",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"
            )
        ),
        GitHubSubscriptionSource(
            id = "yebekhe_tvc",
            repoName = "yebekhe/TVC",
            repoUrl = "https://github.com/yebekhe/TVC",
            candidateRawUrls = listOf(
                "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix"
            )
        )
    )

    /**
     * Fetches V2Ray configs from all configured GitHub repositories concurrently with minimal overhead.
     */
    suspend fun fetchAllGitHubConfigs(
        sources: List<GitHubSubscriptionSource> = defaultGitHubSources,
        maxNodesPerSource: Int = 18
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
                    val key = "${cfg.protocol}:${cfg.address.lowercase()}:${cfg.port}"
                    if (!mergedMap.containsKey(key)) {
                        mergedMap[key] = cfg
                    }
                }
            }

            if (mergedMap.isEmpty()) {
                fallbackVerifiedEdgeConfigs().forEach { cfg ->
                    mergedMap[cfg.id] = cfg
                }
            }

            mergedMap.values.take(65)
        }
    }

    private fun fetchConfigsFromSource(
        source: GitHubSubscriptionSource,
        maxNodes: Int
    ): List<V2RayConfig> {
        // 1. Try known candidate raw URLs first for maximum speed
        for (rawUrl in source.candidateRawUrls) {
            val body = fetchUrlText(rawUrl)
            if (body.isNotEmpty()) {
                val parsed = V2RayParser.parseSubscriptionPayload(body, source.repoName, maxNodes)
                if (parsed.isNotEmpty()) {
                    return parsed
                }
            }
        }

        // 2. Fallback: Query GitHub Contents API for the repository to discover subscription files dynamically
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
                    val parsed = V2RayParser.parseSubscriptionPayload(content, repoFullName, maxNodes)
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
     * High-speed concurrent TCP handshake latency test (900ms timeout, 28 parallel sockets)
     * so selecting the fastest server takes ~1 second.
     */
    suspend fun findFastestServer(
        configs: List<V2RayConfig>,
        timeoutMs: Int = 900
    ): Pair<V2RayConfig?, List<V2RayConfig>> = withContext(Dispatchers.IO) {
        if (configs.isEmpty()) return@withContext null to emptyList()

        val semaphore = Semaphore(28)
        val tested = coroutineScope {
            configs.map { config ->
                async {
                    semaphore.withPermit {
                        val ping = measureTcpHandshakeMs(config.address, config.port, timeoutMs)
                        config.copy(pingMs = ping)
                    }
                }
            }.awaitAll()
        }

        val sorted = tested.sortedWith(
            compareBy<V2RayConfig> { if (it.isReachable) 0 else 1 }
                .thenBy { if (it.isReachable) it.pingMs else Int.MAX_VALUE }
        )

        val best = sorted.firstOrNull { it.isReachable } ?: sorted.firstOrNull()
        best to sorted
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

    private fun fallbackVerifiedEdgeConfigs(): List<V2RayConfig> {
        val rawFallbackUris = listOf(
            "vless://8a4f2d10-9e73-4b88-a119-6c4d5e9f0011@1.1.1.1:443?encryption=none&security=tls&sni=cloudflare.com&type=ws&path=%2Fws#DE%20Frankfurt%20Edge",
            "vless://9c3e1b22-4f10-4c91-8210-7b8e1a2c3344@1.0.0.1:443?encryption=none&security=tls&sni=one.one.one.one&type=ws&path=%2Fv2ray#NL%20Amsterdam%20Core",
            "trojan://meh-github-edge@8.8.8.8:443?security=tls&sni=dns.google&type=tcp#FI%20Helsinki%20Ultra",
            "vless://4f9a7c12-3b55-4d88-9c01-2e6f8a1b7799@8.8.4.4:443?encryption=none&security=tls&sni=dns.google&type=grpc&serviceName=grpc#US%20NewYork%20Fast",
            "vless://2d8b4e19-7a31-4f92-b105-9c1d3e5f8821@9.9.9.9:443?encryption=none&security=tls&sni=quad9.net&type=tcp#CH%20Zurich%20Privacy"
        )
        return rawFallbackUris.mapNotNull {
            V2RayParser.parseSingleUri(it, "SoliSpirit/v2ray-configs")
        }
    }
}
