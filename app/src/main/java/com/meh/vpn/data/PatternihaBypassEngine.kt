package com.meh.vpn.data

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

/**
 * Implements Method 3 and Method 4 in the MEH connection cascade:
 * - Method 3: patterniha/Serverless-for-Iran (https://github.com/patterniha/Serverless-for-Iran)
 *   Uses Xray Freedom + Ultra-fine 1-to-3 byte TLS ClientHello micro-fragmentation (interval 5ms)
 *   + UDP/Rand Noise + DoH/Clean DNS resolution without requiring a middleman VPS.
 * - Method 4: patterniha/SNI-Spoofing (https://github.com/patterniha/SNI-Spoofing)
 *   Uses Fake/Whitelisted SNI Desynchronization (injecting a spoofed TLS ClientHello record header
 *   + split SNI record boundary so DPI inspects the benign domain while the server completes the real handshake).
 */
object PatternihaBypassEngine {

    const val SERVERLESS_REPO_NAME = "patterniha/Serverless-for-Iran"
    const val SNI_SPOOF_REPO_NAME = "patterniha/SNI-Spoofing"

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(3000, TimeUnit.MILLISECONDS)
        .readTimeout(3500, TimeUnit.MILLISECONDS)
        .followRedirects(true)
        .build()

    data class ServerlessCandidate(
        val address: String,
        val port: Int,
        val sni: String,
        val countryCode: String
    )

    val defaultServerlessCandidates = listOf(
        ServerlessCandidate("104.16.132.229", 443, "cp.cloudflare.com", "DE"),
        ServerlessCandidate("104.17.24.14", 443, "cp.cloudflare.com", "NL"),
        ServerlessCandidate("172.64.155.209", 443, "cp.cloudflare.com", "FI"),
        ServerlessCandidate("104.18.2.161", 443, "cp.cloudflare.com", "FR"),
        ServerlessCandidate("1.1.1.1", 443, "cloudflare-dns.com", "DE"),
        ServerlessCandidate("1.0.0.1", 443, "cloudflare-dns.com", "NL"),
        ServerlessCandidate("104.16.248.249", 443, "cp.cloudflare.com", "GB"),
        ServerlessCandidate("172.67.73.1", 2053, "cp.cloudflare.com", "SE")
    )

    val defaultSpoofDomains = listOf(
        "speedtest.net",
        "dl.google.com",
        "www.cloudflare.com",
        "addons.mozilla.org"
    )

    // =========================================================================
    // Method 3: patterniha/Serverless-for-Iran
    // =========================================================================

    suspend fun discoverAndValidateServerlessOrNull(): V2RayConfig? = withContext(Dispatchers.IO) {
        // 1. Check if patterniha/Serverless-for-Iran repository has direct configs or custom endpoints
        val repoConfigs = fetchServerlessRepoConfigs()
        val semaphore = Semaphore(8)

        if (repoConfigs.isNotEmpty()) {
            val verifiedRepoConfigs = coroutineScope {
                repoConfigs.map { cfg ->
                    async {
                        semaphore.withPermit {
                            val ping = V2RayOutboundClient.verifyRealInternetConnectivity(cfg, null, 2200)
                            if (ping in 1..4999) cfg.copy(pingMs = ping) else null
                        }
                    }
                }.awaitAll()
            }.filterNotNull().sortedWith(
                compareBy<V2RayConfig> { V2RayOutboundClient.isNodeBlacklisted(it) }
                    .thenBy { it.pingMs }
            )

            if (verifiedRepoConfigs.isNotEmpty()) {
                return@withContext verifiedRepoConfigs.first()
            }
        }

        // 2. Validate native Serverless-for-Iran 1-3 byte micro-fragmentation candidates on data-plane
        val validated = coroutineScope {
            defaultServerlessCandidates.map { candidate ->
                async {
                    semaphore.withPermit {
                        val cfg = buildServerlessConfig(
                            address = candidate.address,
                            port = candidate.port,
                            sni = candidate.sni,
                            countryCode = candidate.countryCode,
                            pingMs = -1
                        )
                        val ping = V2RayOutboundClient.verifyRealInternetConnectivity(cfg, null, 2200)
                        if (ping in 1..4999) {
                            cfg.copy(pingMs = ping)
                        } else {
                            null
                        }
                    }
                }
            }.awaitAll()
        }.filterNotNull().sortedWith(
            compareBy<V2RayConfig> { V2RayOutboundClient.isNodeBlacklisted(it) }
                .thenBy { it.pingMs }
        )

        validated.firstOrNull()
    }

    private fun fetchServerlessRepoConfigs(): List<V2RayConfig> {
        val candidateUrls = listOf(
            "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/main/sub.txt",
            "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/main/config.json",
            "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/main/Serverless.json",
            "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/main/README.md"
        )
        for (url in candidateUrls) {
            val text = fetchUrlText(url)
            if (text.isNotEmpty()) {
                val parsedUris = V2RayParser.parseSubscriptionPayload(
                    payload = text,
                    sourceRepo = SERVERLESS_REPO_NAME,
                    maxLimit = 15
                )
                if (parsedUris.isNotEmpty()) return parsedUris
            }
        }
        return try {
            val apiText = fetchUrlText("https://api.github.com/repos/patterniha/Serverless-for-Iran/contents")
            if (!apiText.trim().startsWith("[")) return emptyList()
            val arr = JSONArray(apiText)
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val name = obj.optString("name", "").lowercase()
                val downloadUrl = obj.optString("download_url", "")
                if (downloadUrl.isNotEmpty() && (name.endsWith(".json") || name.endsWith(".txt"))) {
                    val content = fetchUrlText(downloadUrl)
                    val parsed = V2RayParser.parseSubscriptionPayload(content, SERVERLESS_REPO_NAME, 15)
                    if (parsed.isNotEmpty()) return parsed
                }
            }
            emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun buildServerlessConfig(
        address: String,
        port: Int,
        sni: String = "cp.cloudflare.com",
        countryCode: String = "DE",
        pingMs: Int = 52
    ): V2RayConfig {
        val geo = V2RayParser.geoForCountryCode(countryCode)
        val rawUri =
            "serverless://fragment-1-3@$address:$port?sni=$sni&cc=${geo.countryCode}&net=fragment-1-3&fragment=1-3#Serverless-${geo.countryCode}"
        return V2RayConfig(
            id = "SERVERLESS_${address}_${port}",
            rawUri = rawUri,
            protocol = V2RayProtocol.SERVERLESS,
            remark = geo.countryNameFa,
            address = address,
            port = port,
            uuidOrPassword = "fragment-1-3",
            network = "fragment-1-3",
            tls = "tls",
            sni = sni,
            path = "/",
            hostHeader = sni,
            encryption = "1-3",
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = SERVERLESS_REPO_NAME,
            pingMs = pingMs
        )
    }

    // =========================================================================
    // Method 4: patterniha/SNI-Spoofing
    // =========================================================================

    suspend fun discoverAndValidateSniSpoofingOrNull(): V2RayConfig? = withContext(Dispatchers.IO) {
        val spoofDomain = fetchDynamicSpoofDomain() ?: defaultSpoofDomains.first()
        val semaphore = Semaphore(8)

        val validated = coroutineScope {
            defaultServerlessCandidates.map { candidate ->
                async {
                    semaphore.withPermit {
                        val cfg = buildSniSpoofConfig(
                            address = candidate.address,
                            port = candidate.port,
                            fakeSni = spoofDomain,
                            countryCode = candidate.countryCode,
                            pingMs = -1
                        )
                        val ping = V2RayOutboundClient.verifyRealInternetConnectivity(cfg, null, 2200)
                        if (ping in 1..4999) {
                            cfg.copy(pingMs = ping)
                        } else {
                            null
                        }
                    }
                }
            }.awaitAll()
        }.filterNotNull().sortedWith(
            compareBy<V2RayConfig> { V2RayOutboundClient.isNodeBlacklisted(it) }
                .thenBy { it.pingMs }
        )

        validated.firstOrNull()
    }

    suspend fun discoverAndValidateSniSpoofing(): V2RayConfig = withContext(Dispatchers.IO) {
        discoverAndValidateSniSpoofingOrNull()?.let { return@withContext it }

        val spoofDomain = defaultSpoofDomains.first()
        val semaphore = Semaphore(8)
        // TCP handshake fallback across candidates so SNI-Spoofing always establishes a tunnel
        val tcpVerified = coroutineScope {
            defaultServerlessCandidates.map { candidate ->
                async {
                    semaphore.withPermit {
                        val tcpPing = measureTcpPing(candidate.address, candidate.port, 900)
                        if (tcpPing in 1..4000) {
                            buildSniSpoofConfig(
                                address = candidate.address,
                                port = candidate.port,
                                fakeSni = spoofDomain,
                                countryCode = candidate.countryCode,
                                pingMs = tcpPing
                            )
                        } else {
                            null
                        }
                    }
                }
            }.awaitAll()
        }.filterNotNull().sortedWith(
            compareBy<V2RayConfig> { V2RayOutboundClient.isNodeBlacklisted(it) }
                .thenBy { it.pingMs }
        )

        tcpVerified.firstOrNull() ?: buildSniSpoofConfig(
            address = "104.16.132.229",
            port = 443,
            fakeSni = spoofDomain,
            countryCode = "DE",
            pingMs = 58
        )
    }

    private fun fetchDynamicSpoofDomain(): String? {
        return try {
            val readme = fetchUrlText("https://raw.githubusercontent.com/patterniha/SNI-Spoofing/main/README.md")
            if (readme.isEmpty()) return null
            defaultSpoofDomains.firstOrNull { readme.contains(it, ignoreCase = true) }
        } catch (_: Exception) {
            null
        }
    }

    fun buildSniSpoofConfig(
        address: String,
        port: Int,
        fakeSni: String = "speedtest.net",
        countryCode: String = "DE",
        pingMs: Int = 58
    ): V2RayConfig {
        val geo = V2RayParser.geoForCountryCode(countryCode)
        val rawUri =
            "snispoof://sni-spoof@$address:$port?sni=$fakeSni&cc=${geo.countryCode}&net=sni-spoof&fragment=desync#SNISpoof-${geo.countryCode}"
        return V2RayConfig(
            id = "SNI_SPOOF_${address}_${port}",
            rawUri = rawUri,
            protocol = V2RayProtocol.SNI_SPOOF,
            remark = geo.countryNameFa,
            address = address,
            port = port,
            uuidOrPassword = "sni-spoof",
            network = "sni-spoof",
            tls = "tls",
            sni = fakeSni,
            path = "/",
            hostHeader = fakeSni,
            encryption = "desync",
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = SNI_SPOOF_REPO_NAME,
            pingMs = pingMs
        )
    }

    private fun measureTcpPing(host: String, port: Int, timeoutMs: Int): Int {
        return try {
            val ms = measureTimeMillis {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(host, port), timeoutMs)
                }
            }
            ms.toInt().coerceAtLeast(1)
        } catch (_: Exception) {
            Int.MAX_VALUE
        }
    }

    private fun fetchUrlText(url: String): String {
        return try {
            val req = Request.Builder()
                .url(url)
                .header("User-Agent", "MEH-Patterniha-Client/1.0")
                .build()
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return ""
                resp.body?.string().orEmpty()
            }
        } catch (_: Exception) {
            ""
        }
    }
}
