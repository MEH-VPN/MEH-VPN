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
  HYSTERIA2("Hysteria2"),
  TUIC("TUICv5"),
  WIREGUARD("WireGuard"),
  SOCKS5("SOCKS5"),
  HTTP_PROXY("HTTP"),
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
  val shortId: String = "",
  val spiderX: String = "",
  /** VLESS `flow` (e.g. `xtls-rprx-vision` or `xtls-rprx-vision-udp443`). */
  val flow: String = "",
  val alterId: Int = 0,
  val cipher: String = "auto",
  val serviceName: String = "",
  val alpn: String = "",
  val seed: String = "",
  val obfs: String = "",
  val obfsPassword: String = "",
  val publicKey: String = "",
  val localAddress: String = "172.16.0.2",
  val reservedBytes: String = "",
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
        "${protocol.name.lowercase()}:${address.lowercase()}:$port:${network.lowercase()}:${sni.lowercase()}:${fragmentProfile.lowercase()}"
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
      "hy2://",
      "hysteria2://",
      "tuic://",
      "wg://",
      "wireguard://",
      "socks://",
      "socks5://",
      "http://",
      "https://",
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
        line.startsWith("hy2://", ignoreCase = true) ||
          line.startsWith("hysteria2://", ignoreCase = true) -> parseHysteria2(line)
        line.startsWith("tuic://", ignoreCase = true) -> parseTuic(line)
        line.startsWith("wg://", ignoreCase = true) ||
          line.startsWith("wireguard://", ignoreCase = true) -> parseWireGuard(line)
        line.startsWith("socks://", ignoreCase = true) ||
          line.startsWith("socks5://", ignoreCase = true) -> parseSocksOrHttpProxy(line, V2RayProtocol.SOCKS5)
        line.startsWith("http://", ignoreCase = true) ||
          line.startsWith("https://", ignoreCase = true) -> parseSocksOrHttpProxy(line, V2RayProtocol.HTTP_PROXY)
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

  private fun normalizeNetworkType(raw: String): String {
    return when (raw.lowercase().trim()) {
      "websocket", "ws" -> "ws"
      "httpupgrade" -> "httpupgrade"
      "grpc", "gun" -> "grpc"
      "xhttp", "splithttp" -> "xhttp"
      "h2", "http" -> "h2"
      "kcp", "mkcp" -> "kcp"
      else -> raw.lowercase().trim().ifEmpty { "tcp" }
    }
  }

  private fun parseVlessOrTrojan(uriString: String, protocol: V2RayProtocol): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "")
    if (withoutScheme.isEmpty()) return null

    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?")

    if (!authorityPart.contains("@")) return null
    val userInfo = decodeUrlSafe(authorityPart.substringBeforeLast("@").trim())
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
    val rawNetwork = queryParams["type"] ?: queryParams["net"] ?: "tcp"
    val network = normalizeNetworkType(rawNetwork)
    val pbk = (queryParams["pbk"] ?: queryParams["publicKey"] ?: "").trim()
    val shortId = (queryParams["sid"] ?: queryParams["shortId"] ?: "").trim()
    val spiderX = (queryParams["spx"] ?: queryParams["spiderX"] ?: "").trim()
    val rawSecurity =
      queryParams["security"]?.lowercase()?.trim()
        ?: when {
          pbk.isNotEmpty() -> "reality"
          protocol == V2RayProtocol.TROJAN -> "tls"
          else -> "none"
        }
    val security = if (rawSecurity == "xtls") "tls" else rawSecurity
    val sni = (queryParams["sni"] ?: queryParams["peer"] ?: queryParams["host"] ?: "").trim().trimEnd('.')
    val hostHeader = (queryParams["host"] ?: queryParams["authority"] ?: sni).trim().trimEnd('.')
    val rawPath = queryParams["path"] ?: "/"
    val cleanPath = rawPath.substringBefore("?ed=").ifEmpty { "/" }
    val serviceName =
      (queryParams["serviceName"] ?: queryParams["path"]?.removePrefix("/") ?: "").trim()
    val encryption = (queryParams["encryption"] ?: "none").lowercase().trim()
    val headerType = (queryParams["headerType"] ?: "none").lowercase().trim()
    val flow = (queryParams["flow"] ?: "").trim()
    val alpn = (queryParams["alpn"] ?: "").trim()
    val seed = (queryParams["seed"] ?: cleanPath.removePrefix("/")).trim()
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
      shortId = shortId,
      spiderX = spiderX,
      flow = flow,
      serviceName = serviceName,
      alpn = alpn,
      seed = seed,
      fragmentProfile = fragmentProfile,
      cipherSuites = csParam,
      rawUri = uriString,
    )
  }

  private fun parseVmess(uriString: String): V2RayConfig? {
    val payload = uriString.substringAfter("://", "").trim()
    if (payload.isEmpty()) return null

    // Support URL-style vmess://uuid@host:port?... in addition to Base64 JSON vmess://ey...
    if (payload.contains("@") && !payload.startsWith("{")) {
      val asVlessStyle = parseVlessOrTrojan(uriString, V2RayProtocol.VMESS)
      if (asVlessStyle != null) {
        val qParams = parseQueryParams(payload.substringBefore("#").substringAfter("?", ""))
        val cipher = (qParams["scy"] ?: qParams["cipher"] ?: qParams["encryption"] ?: "auto").lowercase()
        val aid = qParams["aid"]?.toIntOrNull() ?: 0
        return asVlessStyle.copy(
          protocol = V2RayProtocol.VMESS,
          cipher = if (cipher == "none" && qParams["scy"] == null) "auto" else cipher,
          alterId = aid,
        )
      }
    }

    val jsonStr = decodeBase64Safe(payload.substringBefore("#"))
    if (jsonStr.isEmpty() || !jsonStr.trim().startsWith("{")) return null

    val json = JSONObject(jsonStr)
    val address = json.optString("add", "").trim()
    val port = json.optString("port", "").toIntOrNull() ?: json.optInt("port", -1)
    val id = json.optString("id", "").trim()
    if (address.isEmpty() || port !in 1..65535 || id.isEmpty()) return null

    val ps = decodeUrlSafe(json.optString("ps", ""))
    val rawNet = json.optString("net", "tcp")
    val net = normalizeNetworkType(rawNet)
    val rawTls = json.optString("tls", "none").lowercase().trim()
    val tls = if (rawTls == "1" || rawTls == "true" || rawTls == "tls") "tls" else "none"
    val sni = json.optString("sni", json.optString("host", "")).trim().trimEnd('.')
    val hostHeader = json.optString("host", sni).trim().trimEnd('.')
    val rawPath = json.optString("path", "/")
    val path = rawPath.substringBefore("?ed=").ifEmpty { "/" }
    val headerType = json.optString("type", "none").lowercase().trim()
    val alterId = json.optString("aid", "0").toIntOrNull() ?: json.optInt("aid", 0)
    val cipher =
      json.optString("scy", json.optString("security", "auto")).lowercase().trim().ifEmpty { "auto" }
    val alpn = json.optString("alpn", "").trim()
    val serviceName =
      if (net == "grpc") rawPath.removePrefix("/").trim() else ""

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
      alterId = alterId,
      cipher = cipher,
      serviceName = serviceName,
      alpn = alpn,
      seed = if (net == "kcp") rawPath.removePrefix("/") else "",
      rawUri = uriString,
    )
  }

  private fun parseShadowsocks(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "").trim()
    if (withoutScheme.isEmpty()) return null

    val fragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    // SIP002 puts a "/" before the query ("host:port/?plugin=..."); drop it so host:port parses.
    val mainPart = beforeFragment.substringBefore("?").trimEnd('/')

    val (userInfo, hostPort) =
      if (mainPart.contains("@")) {
        val rawUser = decodeUrlSafe(mainPart.substringBeforeLast("@"))
        val hp = mainPart.substringAfterLast("@")
        val decodedUser =
          if (rawUser.contains(":")) {
            rawUser
          } else {
            decodeBase64Safe(rawUser).ifEmpty { rawUser }
          }
        Pair(decodedUser, hp)
      } else {
        val decoded = decodeBase64Safe(mainPart)
        if (!decoded.contains("@")) return null
        Pair(decoded.substringBeforeLast("@"), decoded.substringAfterLast("@"))
      }

    if (!userInfo.contains(":")) return null
    val method = userInfo.substringBefore(":").trim().lowercase()
    val password = userInfo.substringAfter(":").trim()
    if (method.isEmpty() || password.isEmpty()) return null

    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val qParams = parseQueryParams(queryPart)
    val plugin = qParams["plugin"].orEmpty()
    // Only the simple-obfs "http" mode is implemented. Any other plugin (obfs=tls, v2ray-plugin
    // with tls/ws/quic, shadow-tls, ...) wraps the stream in a transport we do not speak; parsing
    // it as plain Shadowsocks yields a node that connects but never carries traffic.
    if (plugin.isNotBlank() && !isSupportedShadowsocksPlugin(plugin)) return null
    val headerType = if (plugin.contains("obfs=http", ignoreCase = true)) "http" else "none"
    val obfsHost =
      Regex("obfs-host=([^;&]+)", RegexOption.IGNORE_CASE)
        .find(plugin)
        ?.groupValues
        ?.getOrNull(1)
        .orEmpty()

    val remarks = sanitizeRemarks(decodeUrlSafe(fragment), V2RayProtocol.SHADOWSOCKS, host, port)
    return V2RayConfig(
      id = "SS_${host}_$port",
      protocol = V2RayProtocol.SHADOWSOCKS,
      remarks = remarks,
      address = host,
      port = port,
      authId = "$method:$password",
      cipher = method,
      network = "tcp",
      security = "ss",
      hostHeader = obfsHost,
      headerType = headerType,
      rawUri = uriString,
    )
  }

  private fun isSupportedShadowsocksPlugin(plugin: String): Boolean {
    val parts = plugin.split(";").map { it.trim() }.filter { it.isNotEmpty() }
    val name = parts.firstOrNull()?.lowercase().orEmpty()
    val nameless = parts.firstOrNull()?.startsWith("obfs=", ignoreCase = true) == true
    if (name != "obfs-local" && name != "simple-obfs" && !nameless) return false
    val mode =
      parts.firstOrNull { it.startsWith("obfs=", ignoreCase = true) }
        ?.substringAfter("=")?.trim()?.lowercase()
    return mode == "http"
  }

  private fun parseHysteria2(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "").trim()
    if (withoutScheme.isEmpty()) return null
    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?").removeSuffix("/")

    val authPassword =
      if (authorityPart.contains("@")) {
        decodeUrlSafe(authorityPart.substringBeforeLast("@").trim())
      } else {
        ""
      }
    val hostPort = authorityPart.substringAfterLast("@").trim()
    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val qParams = parseQueryParams(queryPart)
    val password = authPassword.ifEmpty { qParams["auth"] ?: qParams["password"] ?: "" }
    if (password.isEmpty()) return null

    val sni = (qParams["sni"] ?: qParams["peer"] ?: host).trim().trimEnd('.')
    val obfs = (qParams["obfs"] ?: "").lowercase().trim()
    val obfsPassword = (qParams["obfs-password"] ?: qParams["obfsParam"] ?: "").trim()
    val alpn = (qParams["alpn"] ?: "h3").trim()
    val remarks = sanitizeRemarks(decodeUrlSafe(rawFragment), V2RayProtocol.HYSTERIA2, host, port)

    return V2RayConfig(
      id = "HY2_${host}_$port",
      protocol = V2RayProtocol.HYSTERIA2,
      remarks = remarks,
      address = host,
      port = port,
      authId = password,
      network = "quic",
      security = "tls",
      sni = sni,
      alpn = alpn,
      obfs = obfs,
      obfsPassword = obfsPassword,
      rawUri = uriString,
    )
  }

  private fun parseTuic(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "").trim()
    if (withoutScheme.isEmpty() || !withoutScheme.contains("@")) return null
    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?").removeSuffix("/")

    val rawUserInfo = decodeUrlSafe(authorityPart.substringBeforeLast("@").trim())
    val hostPort = authorityPart.substringAfterLast("@").trim()
    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val qParams = parseQueryParams(queryPart)

    val authId =
      if (rawUserInfo.contains(":")) {
        rawUserInfo
      } else {
        val pass = qParams["password"] ?: qParams["token"] ?: ""
        "$rawUserInfo:$pass"
      }
    val sni = (qParams["sni"] ?: host).trim().trimEnd('.')
    val alpn = (qParams["alpn"] ?: "h3").trim()
    val remarks = sanitizeRemarks(decodeUrlSafe(rawFragment), V2RayProtocol.TUIC, host, port)

    return V2RayConfig(
      id = "TUIC_${host}_$port",
      protocol = V2RayProtocol.TUIC,
      remarks = remarks,
      address = host,
      port = port,
      authId = authId,
      network = "quic",
      security = "tls",
      sni = sni,
      alpn = alpn,
      rawUri = uriString,
    )
  }

  private fun parseWireGuard(uriString: String): V2RayConfig? {
    val withoutScheme = uriString.substringAfter("://", "").trim()
    if (withoutScheme.isEmpty()) return null
    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#")
    val queryPart = beforeFragment.substringAfter("?", "")
    val authorityPart = beforeFragment.substringBefore("?").removeSuffix("/")

    val privateKeyFromAuth =
      if (authorityPart.contains("@")) {
        decodeUrlSafe(authorityPart.substringBeforeLast("@").trim())
      } else {
        ""
      }
    val hostPort = authorityPart.substringAfterLast("@").trim()
    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val qParams = parseQueryParams(queryPart)

    val privateKey =
      privateKeyFromAuth.ifEmpty {
        qParams["privateKey"] ?: qParams["private_key"] ?: qParams["secretKey"] ?: ""
      }
    val publicKey =
      (qParams["publicKey"] ?: qParams["public_key"] ?: qParams["peerPublicKey"] ?: "").trim()
    if (privateKey.isEmpty() || publicKey.isEmpty()) return null

    val localAddress =
      (qParams["address"] ?: qParams["ip"] ?: "172.16.0.2/32")
        .substringBefore(",")
        .substringBefore("/")
        .trim()
        .ifEmpty { "172.16.0.2" }
    val reserved = (qParams["reserved"] ?: "").trim()
    val remarks = sanitizeRemarks(decodeUrlSafe(rawFragment), V2RayProtocol.WIREGUARD, host, port)

    return V2RayConfig(
      id = "WG_${host}_$port",
      protocol = V2RayProtocol.WIREGUARD,
      remarks = remarks,
      address = host,
      port = port,
      authId = privateKey,
      publicKey = publicKey,
      localAddress = localAddress,
      reservedBytes = reserved,
      network = "udp",
      security = "noise",
      rawUri = uriString,
    )
  }

  private fun parseSocksOrHttpProxy(uriString: String, protocol: V2RayProtocol): V2RayConfig? {
    val isTls = uriString.startsWith("https://", ignoreCase = true)
    val withoutScheme = uriString.substringAfter("://", "").trim()
    if (withoutScheme.isEmpty()) return null
    val rawFragment = withoutScheme.substringAfter("#", "")
    val beforeFragment = withoutScheme.substringBefore("#").substringBefore("?").removeSuffix("/")

    val (userInfo, hostPort) =
      if (beforeFragment.contains("@")) {
        val rawUser = decodeUrlSafe(beforeFragment.substringBeforeLast("@"))
        val hp = beforeFragment.substringAfterLast("@")
        val decodedUser =
          if (rawUser.contains(":")) {
            rawUser
          } else {
            decodeBase64Safe(rawUser).ifEmpty { rawUser }
          }
        Pair(decodedUser, hp)
      } else {
        val decodedAll = decodeBase64Safe(beforeFragment)
        if (decodedAll.contains("@")) {
          Pair(decodedAll.substringBeforeLast("@"), decodedAll.substringAfterLast("@"))
        } else {
          // For plain http:// or https:// without @, require explicit port so normal web URLs aren't mistaken for proxies
          if (protocol == V2RayProtocol.HTTP_PROXY && !beforeFragment.contains(":")) return null
          Pair("", beforeFragment)
        }
      }

    // Reject path-bearing web URLs like https://github.com/foo/bar
    if (hostPort.contains("/")) return null
    val (host, port) = parseHostAndPort(hostPort) ?: return null
    val remarks = sanitizeRemarks(decodeUrlSafe(rawFragment), protocol, host, port)

    return V2RayConfig(
      id = "${protocol.name}_${host}_$port",
      protocol = protocol,
      remarks = remarks,
      address = host,
      port = port,
      authId = userInfo,
      network = "tcp",
      security = if (isTls) "tls" else "none",
      sni = if (isTls) host else "",
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

  fun decodeBase64Safe(input: String): String {
    val bytes = decodeBase64BytesSafe(input) ?: return ""
    return try {
      val text = String(bytes, Charsets.UTF_8)
      if (text.isNotBlank()) text else ""
    } catch (_: Throwable) {
      ""
    }
  }

  fun decodeBase64BytesSafe(input: String): ByteArray? {
    val cleaned = input.trim().replace("\n", "").replace("\r", "")
    if (cleaned.isEmpty()) return null
    val padded =
      when (cleaned.length % 4) {
        2 -> "$cleaned=="
        3 -> "$cleaned="
        else -> cleaned
      }

    try {
      val normalized = padded.replace('-', '+').replace('_', '/')
      return java.util.Base64.getDecoder().decode(normalized)
    } catch (_: Throwable) {}

    try {
      return android.util.Base64.decode(
        padded,
        android.util.Base64.DEFAULT or android.util.Base64.URL_SAFE,
      )
    } catch (_: Throwable) {}

    return null
  }
}
