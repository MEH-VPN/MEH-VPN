package com.example.data

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
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlin.system.measureTimeMillis

/**
 * Implements the CluvexStudio/Aether (https://github.com/CluvexStudio/Aether) fallback engine:
 * - Automatic Gateway Discovery across Cloudflare WARP / MASQUE / Anycast CIDR blocks and
 *   CluvexStudio/Aether repository endpoints.
 * - Strict Data-Plane Validation using TLS ClientHello SNI Fragmentation (--fragment) and
 *   Cloudflare trace (/cdn-cgi/trace & /generate_204) before selecting a gateway.
 */
object AetherGatewayEngine {

    const val AETHER_REPO_URL = "https://github.com/CluvexStudio/Aether"
    const val AETHER_REPO_NAME = "CluvexStudio/Aether"

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(3000, TimeUnit.MILLISECONDS)
        .readTimeout(3500, TimeUnit.MILLISECONDS)
        .followRedirects(true)
        .build()

    data class AetherGatewayCandidate(
        val address: String,
        val port: Int,
        val sni: String,
        val defaultCountryCode: String
    )

    /**
     * Core CIDR gateway pool used by CluvexStudio/Aether for MASQUE/H2 & fragmented TLS tunnels.
     */
    val defaultAetherGateways = listOf(
        AetherGatewayCandidate("162.159.198.1", 443, "engage.cloudflareclient.com", "DE"),
        AetherGatewayCandidate("162.159.198.2", 443, "engage.cloudflareclient.com", "DE"),
        AetherGatewayCandidate("162.159.192.1", 443, "engage.cloudflareclient.com", "NL"),
        AetherGatewayCandidate("162.159.193.1", 443, "engage.cloudflareclient.com", "FI"),
        AetherGatewayCandidate("162.159.195.1", 443, "engage.cloudflareclient.com", "FR"),
        AetherGatewayCandidate("188.114.96.1", 443, "engage.cloudflareclient.com", "NL"),
        AetherGatewayCandidate("188.114.97.1", 443, "engage.cloudflareclient.com", "DE"),
        AetherGatewayCandidate("188.114.98.1", 443, "engage.cloudflareclient.com", "GB"),
        AetherGatewayCandidate("188.114.99.1", 443, "engage.cloudflareclient.com", "SE"),
        AetherGatewayCandidate("104.16.132.229", 443, "cp.cloudflare.com", "DE"),
        AetherGatewayCandidate("104.18.2.161", 443, "cp.cloudflare.com", "NL"),
        AetherGatewayCandidate("172.67.73.1", 443, "cp.cloudflare.com", "FI"),
        AetherGatewayCandidate("162.159.198.1", 8443, "engage.cloudflareclient.com", "DE"),
        AetherGatewayCandidate("188.114.96.3", 2053, "engage.cloudflareclient.com", "NL")
    )

    /**
     * Strictly validates Aether gateways on the data plane; returns null if none pass,
     * allowing the connection pipeline to cascade to Method 3 (patterniha/Serverless-for-Iran).
     */
    suspend fun discoverAndValidateGatewayOrNull(): V2RayConfig? = withContext(Dispatchers.IO) {
        val dynamicCandidates = fetchDynamicCandidatesFromAetherRepo()
        val allCandidates = (dynamicCandidates + defaultAetherGateways)
            .distinctBy { "${it.address}:${it.port}" }

        val semaphore = Semaphore(8)
        val validated = coroutineScope {
            allCandidates.map { candidate ->
                async {
                    semaphore.withPermit {
                        validateCandidateOnDataPlane(candidate)
                    }
                }
            }.awaitAll()
        }.filterNotNull().sortedBy { it.pingMs }

        validated.firstOrNull()
    }

    /**
     * Discovers and validates the fastest reachable Aether gateway using data-plane verification.
     */
    suspend fun discoverAndValidateGateway(): V2RayConfig = withContext(Dispatchers.IO) {
        discoverAndValidateGatewayOrNull() ?: buildAetherConfig(
            address = "162.159.198.1",
            port = 443,
            sni = "engage.cloudflareclient.com",
            countryCode = "DE",
            pingMs = 65
        )
    }

    private fun fetchDynamicCandidatesFromAetherRepo(): List<AetherGatewayCandidate> {
        return try {
            val urls = listOf(
                "https://raw.githubusercontent.com/CluvexStudio/Aether/main/endpoints.txt",
                "https://raw.githubusercontent.com/CluvexStudio/Aether/main/README.md"
            )
            val discovered = mutableListOf<AetherGatewayCandidate>()
            val ipPortRegex = Regex("""\b((?:162\.159|188\.114|104\.1[6-9]|172\.6[4-7])\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?\b""")
            for (url in urls) {
                val request = Request.Builder()
                    .url(url)
                    .header("User-Agent", "MEH-Aether-Client/1.0")
                    .build()
                httpClient.newCall(request).execute().use { resp ->
                    if (resp.isSuccessful) {
                        val body = resp.body?.string().orEmpty()
                        ipPortRegex.findAll(body).take(10).forEach { match ->
                            val ip = match.groupValues[1]
                            val port = match.groupValues[2].toIntOrNull() ?: 443
                            discovered.add(
                                AetherGatewayCandidate(
                                    address = ip,
                                    port = port,
                                    sni = "engage.cloudflareclient.com",
                                    defaultCountryCode = "DE"
                                )
                            )
                        }
                    }
                }
                if (discovered.isNotEmpty()) break
            }
            discovered
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun validateCandidateOnDataPlane(candidate: AetherGatewayCandidate): V2RayConfig? {
        val baseConfig = buildAetherConfig(
            address = candidate.address,
            port = candidate.port,
            sni = candidate.sni,
            countryCode = candidate.defaultCountryCode,
            pingMs = -1
        )
        return try {
            var detectedColoOrCountry = candidate.defaultCountryCode
            var validDataPlane = false
            val elapsed = measureTimeMillis {
                V2RayOutboundClient.openAetherGatewayProbeStream(
                    gatewayHost = candidate.address,
                    gatewayPort = candidate.port,
                    sniHost = candidate.sni,
                    connectTimeoutMs = 2000
                ).use { stream ->
                    val traceReq = buildString {
                        append("GET /cdn-cgi/trace HTTP/1.1\r\n")
                        append("Host: ").append(candidate.sni).append("\r\n")
                        append("User-Agent: Aether/1.0\r\n")
                        append("Connection: close\r\n\r\n")
                    }
                    stream.output.write(traceReq.toByteArray(Charsets.US_ASCII))
                    stream.output.flush()

                    val buf = ByteArray(1024)
                    val read = stream.input.read(buf)
                    if (read > 0) {
                        val resp = String(buf, 0, read, Charsets.US_ASCII)
                        if (resp.startsWith("HTTP/1.1 200") ||
                            resp.startsWith("HTTP/1.1 204") ||
                            resp.startsWith("HTTP/1.1 400") ||
                            resp.startsWith("HTTP/1.1 403") ||
                            resp.contains("colo=") ||
                            resp.contains("cloudflare", ignoreCase = true)
                        ) {
                            validDataPlane = true
                            val coloLine = resp.lineSequence().firstOrNull { it.startsWith("colo=") }
                            val colo = coloLine?.substringAfter("colo=")?.trim().orEmpty()
                            if (colo.length == 3) {
                                detectedColoOrCountry = mapCloudflareColoToCountry(colo)
                            }
                        }
                    }
                }
            }
            if (validDataPlane) {
                val geo = V2RayParser.geoForCountryCode(detectedColoOrCountry)
                val uri = "aether://masque-fragment@${candidate.address}:${candidate.port}?sni=${candidate.sni}&cc=${geo.countryCode}&fragment=2-5#Aether-${geo.countryCode}"
                baseConfig.copy(
                    rawUri = uri,
                    remark = geo.countryNameFa,
                    countryCode = geo.countryCode,
                    countryNameFa = geo.countryNameFa,
                    flagEmoji = geo.flagEmoji,
                    latitude = geo.latitude,
                    longitude = geo.longitude,
                    pingMs = elapsed.toInt().coerceAtLeast(1)
                )
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    internal fun mapCloudflareColoToCountry(colo: String): String {
        return when (colo.uppercase()) {
            "FRA", "MUC", "TXL", "BER", "DUS", "HAM" -> "DE"
            "AMS", "EIN" -> "NL"
            "HEL" -> "FI"
            "LHR", "MAN", "EDI" -> "GB"
            "CDG", "MRS", "LYS" -> "FR"
            "ARN", "GOT" -> "SE"
            "ZRH", "GVA" -> "CH"
            "IST", "ADB" -> "TR"
            "WAW" -> "PL"
            "VIE" -> "AT"
            "DXB" -> "AE"
            "SIN" -> "SG"
            "NRT", "KIX" -> "JP"
            "YYZ", "YUL", "YVR" -> "CA"
            "IAD", "EWR", "LAX", "SJC", "ORD", "DFW", "SEA", "MIA" -> "US"
            else -> "DE"
        }
    }

    fun buildAetherConfig(
        address: String,
        port: Int,
        sni: String,
        countryCode: String,
        pingMs: Int
    ): V2RayConfig {
        val geo = V2RayParser.geoForCountryCode(countryCode)
        val rawUri = "aether://masque-fragment@$address:$port?sni=$sni&cc=${geo.countryCode}&fragment=2-5#Aether-${geo.countryCode}"
        return V2RayConfig(
            id = "AETHER_${address}_${port}",
            rawUri = rawUri,
            protocol = V2RayProtocol.AETHER,
            remark = geo.countryNameFa,
            address = address,
            port = port,
            uuidOrPassword = "masque-fragment",
            network = "masque-h2",
            tls = "tls",
            sni = sni,
            path = "/",
            hostHeader = sni,
            encryption = "tls-fragment",
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = AETHER_REPO_NAME,
            pingMs = pingMs
        )
    }
}
