package com.example.model

import com.example.vpn.GfwKnockerXrayCore
import java.net.URLDecoder
import org.json.JSONObject

enum class V2RayProtocol(val label: String) {
  VLESS("VLESS"),
  MVLESS("MVLESS"),
  JVLESS("JVLESS"),
  VMESS("VMess"),
  TROJAN("Trojan"),
  SHADOWSOCKS("SS"),
  SERVERLESS("Serverless"),
}

data class V2RayConfig(
  val id: String,
  val protocol: V2RayProtocol,
  val remarks: String,
  val address: String,
  val port: Int,
  val authId: String,
  val network: String = "tcp",
  val security: String = "none",
  val sni: String = "",
  val hostHeader: String = "",
  val path: String = "",
  val encryption: String = "none",
  val headerType: String = "none",
  val pbk: String = "",
  val fragmentProfile: String = "direct_tls",
  val cipherSuites: String = "",
  val rawUri: String,
  val resolvedIp: String = "",
  val latencyMs: Long = -1L,
  val speedScore: Double = 0.0,
) {
  val endpointKey: String
    get() =
      if (protocol == V2RayProtocol.SERVERLESS) {
        "serverless:${fragmentProfile.lowercase()}:${address.lowercase()}:$port"
      } else {
        "${address.lowercase()}:$port:${sni.lowercase()}:${fragmentProfile.lowercase()}"
      }

  val cleanTitle: String
    get() {
      val trimmed = remarks.trim()
      return if (trimmed.isNotEmpty() && trimmed.length <= 32) {
        trimmed
      } else if (trimmed.length > 32) {
        trimmed.take(30).trim() + "…"
      } else {
        "${protocol.label} ($address:$port)"
      }
    }

  /**
   * Builds a GFW-knocker/Xray-core + Patterniha JSON configuration.
   */
  fun toV2RayCoreJson(): String {
    return GfwKnockerXrayCore.buildXrayCoreJson(this)
  }

  companion object {
    /**
     * Creates a direct Serverless configuration (`patterniha/Serverless-for-Iran` Frag-A, Frag-B, Aether, or SNI-Spoof).
     */
    fun createPatternihaServerless(
      profileId: String,
      remarks: String,
      cleanEdgeIp: String = "188.114.98.0",
    ): V2RayConfig {
      val uri = "serverless://patterniha@$cleanEdgeIp:443?profile=$profileId#$remarks"
      return V2RayConfig(
        id = "SERVERLESS_${profileId}_$cleanEdgeIp",
        protocol = V2RayProtocol.SERVERLESS,
        remarks = remarks,
        address = cleanEdgeIp,
        port = 443,
        authId = "patterniha-serverless",
        network = "tcp",
        security = "tls",
        sni = "challenges.cloudflare.com",
        hostHeader = "challenges.cloudflare.com",
        path = "/",
        fragmentProfile = profileId,
        rawUri = uri,
        resolvedIp = cleanEdgeIp,
      )
    }
  }
}

object V2RayConfigParser {

  private val SUPPORTED_SCHEMES =
    listOf(
      "vless://",
      "mvless://",
      "jvless://",
      "vmess://",
      "trojan://",
      "ss://",
      "serverless://",
    )

  /**
   * Parses raw subscription text (either plain multi-line URIs or Base64-encoded subscription content)
   * into validated, deduplicated [V2RayConfig] items.
   */
  fun parseSubscriptionContent(rawText: String): List<V2RayConfig> {
    val trimmed = rawText.trim()
    if (trimmed.isEmpty()) return emptyList()

    val decodedBlock =
      if (SUPPORTED_SCHEMES.any { trimmed.contains(it, ignoreCase = true) }) {
        trimmed
      } else {
        decodeBase64Safe(trimmed).ifEmpty { trimmed }
      }

    val results = mutableListOf<V2RayConfig>()
    val seenEndpoints = HashSet<String>()

    decodedBlock
      .lineSequence()
      .map { it.trim() }
      .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("//") }
      .forEach { line ->
        val config = parseSingleUri(line)
        if (config != null && isValidHostAndPort(config.address, config.port)) {
          if (seenEndpoints.add(config.endpointKey)) {
            results.add(config)
          }
        }
      }

    return results
  }

  fun parseSingleUri(uriString: String): V2RayConfig? {
    // Normalize HTML-escaped ampersands common in scraped subscription feeds
    val line = uriString.trim().replace("&amp;", "&")
    return try {
      when {
        line.startsWith("serverless://", ignoreCase = true) -> parseServerlessUri(line)
        line.startsWith("vless://", ignoreCase = true) -> parseVlessOrTrojan(line, V2RayProtocol.VLESS)
        line.startsWith("mvless://", ignoreCase = true) -> parseVlessOrTrojan(line, V2RayProtocol.MVLESS)
        line.startsWith("jvless://", ignoreCase = true) -> parseVlessOrTrojan(line, V2RayProtocol.JVLESS)
        line.startsWith("trojan://", ignoreCase = true) -> parseVlessOrTrojan(line, V2RayProtocol.TROJAN)
        line.startsWith("vmess://", ignoreCase = true) -> parseVmess(line)
        line.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(line)
        else -> null
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun parseServerlessUri(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "")
    val rawFragment = decodeUrlSafe(withoutScheme.substringAfter("#", "Patterniha Serverless"))
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?")
    val hostPort = authorityPart.substringAfterLast("@", authorityPart)
    val (host, port) = parseHostAndPort(hostPort) ?: Pair("188.114.98.0", 443)
    val queryParams = parseQueryParams(queryPart)
    val profile = queryParams["profile"] ?: "patterniha_frag_a"
    return V2RayConfig.createPatternihaServerless(
      profileId = profile,
      remarks = rawFragment.ifBlank { "Patterniha Serverless" },
      cleanEdgeIp = host,
    ).copy(port = port, rawUri = uriString)
  }

  private fun parseVlessOrTrojan(uriString: String, protocol: V2RayProtocol): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "")
    if (withoutScheme.isEmpty()) return null

    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?")

    if (!authorityPart.contains("@")) return null
    val userInfo = authorityPart.substringBeforeLast("@").trim()
    val hostPort = authorityPart.substringAfterLast("@").trim()
    if (userInfo.isEmpty() || hostPort.isEmpty()) return null

    val (parsedHost, parsedPort) = parseHostAndPort(hostPort) ?: return null
    val queryParams = parseQueryParams(queryPart)
    val decodedFragment = decodeUrlSafe(rawFragment)

    // In patterniha/Free-Configs, Sni-Spoofing variants use 127.0.0.1:40443 to represent local
    // SNI-Spoofing relay to Cloudflare edge 188.114.98.0:443. Map them natively to our built-in SNI-Spoofing engine!
    val isPatternihaLocalSniRelay =
      (parsedHost == "127.0.0.1" && parsedPort == 40443) ||
        decodedFragment.contains("Sni-Spoofing", ignoreCase = true)

    val host = if (parsedHost == "127.0.0.1" && parsedPort == 40443) "188.114.98.0" else parsedHost
    val port = if (parsedHost == "127.0.0.1" && parsedPort == 40443) 443 else parsedPort

    val cleanRemarks = sanitizeRemarks(decodedFragment, protocol, host, port)
    val rawNetwork = queryParams["type"]?.lowercase()?.trim() ?: "tcp"
    val network = if (rawNetwork == "websocket") "ws" else rawNetwork
    val security =
      queryParams["security"]?.lowercase()?.trim()
        ?: if (protocol == V2RayProtocol.TROJAN) "tls" else "none"
    val sni = (queryParams["sni"] ?: queryParams["host"] ?: "").trim().trimEnd('.')
    val hostHeader = (queryParams["host"] ?: sni).trim().trimEnd('.')
    val rawPath = queryParams["path"] ?: "/"
    val cleanPath = rawPath.substringBefore("?ed=").ifEmpty { "/" }
    val encryption = (queryParams["encryption"] ?: "none").lowercase().trim()
    val headerType = (queryParams["headerType"] ?: "none").lowercase().trim()
    val pbk = (queryParams["pbk"] ?: "").trim()
    val fmParam = queryParams["fm"].orEmpty()
    val csParam = queryParams["cs"].orEmpty()
    val explicitProfile = queryParams["mehProfile"].orEmpty()

    val fragmentProfile =
      when {
        explicitProfile.isNotEmpty() -> explicitProfile
        isPatternihaLocalSniRelay -> "patterniha_sni_spoof"
        fmParam.contains("\"6\"") && fmParam.contains("\"98\"") -> "patterniha_frag_a"
        fmParam.contains("\"104\"") || decodedFragment.startsWith("F&F", ignoreCase = true) ->
          "patterniha_frag_b"
        else -> "direct_tls"
      }

    return V2RayConfig(
      id = "${protocol.name}_${host}_${port}_$fragmentProfile",
      protocol = protocol,
      remarks = cleanRemarks,
      address = host,
      port = port,
      authId = userInfo,
      network = network,
      security = security,
      sni = sni,
      hostHeader = hostHeader,
      path = cleanPath,
      encryption = encryption,
      headerType = headerType,
      pbk = pbk,
      fragmentProfile = fragmentProfile,
      cipherSuites = csParam,
      rawUri = uriString,
    )
  }

  private fun parseVmess(uriString: String): V2RayConfig? {
    val payload = uriString.substringAfter("vmess://", "").trim()
    if (payload.isEmpty()) return null

    val jsonStr = decodeBase64Safe(payload)
    if (jsonStr.isEmpty() || !jsonStr.trim().startsWith("{")) return null

    val json = JSONObject(jsonStr)
    val address = json.optString("add", "").trim()
    val port = json.optString("port", "").toIntOrNull() ?: json.optInt("port", -1)
    val id = json.optString("id", "").trim()
    if (address.isEmpty() || port !in 1..65535 || id.isEmpty()) return null

    val ps = decodeUrlSafe(json.optString("ps", ""))
    val net = json.optString("net", "tcp").lowercase()
    val tls = json.optString("tls", "none").lowercase().ifEmpty { "none" }
    val sni = json.optString("sni", json.optString("host", ""))
    val hostHeader = json.optString("host", "")
    val path = json.optString("path", "").substringBefore("?ed=")
    val headerType = json.optString("type", "none").lowercase()

    return V2RayConfig(
      id = "VMESS_${address}_$port",
      protocol = V2RayProtocol.VMESS,
      remarks = sanitizeRemarks(ps, V2RayProtocol.VMESS, address, port),
      address = address,
      port = port,
      authId = id,
      network = net,
      security = tls,
      sni = sni,
      hostHeader = hostHeader,
      path = path,
      headerType = headerType,
      rawUri = uriString,
    )
  }

  private fun parseShadowsocks(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("ss://", "").trim()
    if (withoutScheme.isEmpty()) return null

    val fragment = withoutScheme.substringAfter("#", "")
    val mainPart = withoutScheme.substringBefore("#").substringBefore("?")

    val (userInfo, hostPort) =
      if (mainPart.contains("@")) {
        val rawUser = mainPart.substringBeforeLast("@")
        val hp = mainPart.substringAfterLast("@")
        Pair(decodeBase64Safe(rawUser).ifEmpty { rawUser }, hp)
      } else {
        val decoded = decodeBase64Safe(mainPart)
        if (!decoded.contains("@")) return null
        Pair(decoded.substringBeforeLast("@"), decoded.substringAfterLast("@"))
      }

    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val remarks = sanitizeRemarks(decodeUrlSafe(fragment), V2RayProtocol.SHADOWSOCKS, host, port)
    return V2RayConfig(
      id = "SS_${host}_$port",
      protocol = V2RayProtocol.SHADOWSOCKS,
      remarks = remarks,
      address = host,
      port = port,
      authId = userInfo,
      network = "tcp",
      security = "ss",
      rawUri = uriString,
    )
  }

  private fun parseHostAndPort(hostPort: String): Pair<String, Int>? {
    val trimmed = hostPort.trim()
    return if (trimmed.startsWith("[")) {
      val host = trimmed.substringAfter("[").substringBefore("]", "")
      val portStr = trimmed.substringAfter("]:", "443")
      val port = portStr.toIntOrNull() ?: return null
      if (host.isEmpty() || port !in 1..65535) null else Pair(host, port)
    } else {
      val host = trimmed.substringBeforeLast(":").trim()
      val port =
        if (trimmed.contains(":")) {
          trimmed.substringAfterLast(":", "").toIntOrNull() ?: return null
        } else {
          443
        }
      if (host.isEmpty() || port !in 1..65535) null else Pair(host, port)
    }
  }

  private fun parseQueryParams(query: String): Map<String, String> {
    if (query.isBlank()) return emptyMap()
    val map = mutableMapOf<String, String>()
    query.split("&").forEach { pair ->
      val key = pair.substringBefore("=", "").trim()
      val value = decodeUrlSafe(pair.substringAfter("=", ""))
      if (key.isNotEmpty()) {
        map[key] = value
      }
    }
    return map
  }

  private fun isValidHostAndPort(host: String, port: Int): Boolean {
    if (port !in 1..65535) return false
    if (host.length < 3 || host.contains(" ") || host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost") {
      return false
    }
    return true
  }

  private fun sanitizeRemarks(raw: String, protocol: V2RayProtocol, host: String, port: Int): String {
    val cleaned =
      raw
        .replace(Regex("(?:@\\S+|t\\.me/\\S+|https?://\\S+)", RegexOption.IGNORE_CASE), " ")
        .replace(Regex("\\s+"), " ")
        .trim()
    return if (cleaned.length >= 2) {
      cleaned
    } else {
      "${protocol.label} • $host:$port"
    }
  }

  private fun decodeUrlSafe(value: String): String {
    if (value.isEmpty()) return ""
    return try {
      URLDecoder.decode(value, "UTF-8")
    } catch (_: Exception) {
      value
    }
  }

  private fun decodeBase64Safe(input: String): String {
    val cleaned = input.trim().replace("\n", "").replace("\r", "")
    if (cleaned.isEmpty()) return ""
    val padded =
      when (cleaned.length % 4) {
        2 -> "$cleaned=="
        3 -> "$cleaned="
        else -> cleaned
      }

    try {
      val normalized = padded.replace('-', '+').replace('_', '/')
      val decoded = java.util.Base64.getDecoder().decode(normalized)
      val text = String(decoded, Charsets.UTF_8)
      if (text.isNotBlank()) return text
    } catch (_: Throwable) {}

    try {
      val decoded =
        android.util.Base64.decode(
          padded,
          android.util.Base64.DEFAULT or android.util.Base64.URL_SAFE,
        )
      if (decoded != null) {
        val text = String(decoded, Charsets.UTF_8)
        if (text.isNotBlank()) return text
      }
    } catch (_: Throwable) {}

    return ""
  }
}
