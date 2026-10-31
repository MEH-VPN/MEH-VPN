package com.meh.vpn.data

import android.util.Base64
import com.meh.vpn.model.GeoLocationInfo
import com.meh.vpn.model.V2RayConfig
import com.meh.vpn.model.V2RayProtocol
import org.json.JSONObject
import java.net.URLDecoder
import kotlin.math.abs

object V2RayParser {

    private data class RegionRule(
        val keywords: List<String>,
        val geo: GeoLocationInfo
    )

    private val knownGeoLocations = listOf(
        RegionRule(
            listOf("germany", "deutschland", "frankfurt", "falkenstein", "nuremberg", "berlin", "muc", "fra", "txl", "de-", "_de", "🇩🇪", " de "),
            GeoLocationInfo("DE", "آلمان", "🇩🇪", 50.1109f, 8.6821f)
        ),
        RegionRule(
            listOf("netherlands", "amsterdam", "holland", "rotterdam", "ams", "nl-", "_nl", "🇳🇱", " nl "),
            GeoLocationInfo("NL", "هلند", "🇳🇱", 52.3676f, 4.9041f)
        ),
        RegionRule(
            listOf("finland", "helsinki", "hel", "fi-", "_fi", "🇫🇮", " fi "),
            GeoLocationInfo("FI", "فنلاند", "🇫🇮", 60.1699f, 24.9384f)
        ),
        RegionRule(
            listOf("united states", "usa", "us-", "_us", "new york", "los angeles", "dallas", "seattle", "ashburn", "iad", "ewr", "lax", "sjc", "ord", "🇺🇸", " us "),
            GeoLocationInfo("US", "آمریکا", "🇺🇸", 40.7128f, -74.0060f)
        ),
        RegionRule(
            listOf("united kingdom", "uk-", "_uk", "london", "england", "britain", "manchester", "lhr", "man", "🇬🇧", " gb ", " uk "),
            GeoLocationInfo("GB", "انگلیس", "🇬🇧", 51.5072f, -0.1276f)
        ),
        RegionRule(
            listOf("france", "paris", "strasbourg", "marseille", "cdg", "mrs", "fr-", "_fr", "🇫🇷", " fr "),
            GeoLocationInfo("FR", "فرانسه", "🇫🇷", 48.8566f, 2.3522f)
        ),
        RegionRule(
            listOf("turkey", "istanbul", "ankara", "izmir", "ist", "tr-", "_tr", "🇹🇷", " tr "),
            GeoLocationInfo("TR", "ترکیه", "🇹🇷", 41.0082f, 28.9784f)
        ),
        RegionRule(
            listOf("singapore", "sin", "sg-", "_sg", "🇸🇬", " sg "),
            GeoLocationInfo("SG", "سنگاپور", "🇸🇬", 1.3521f, 103.8198f)
        ),
        RegionRule(
            listOf("japan", "tokyo", "osaka", "nrt", "kix", "jp-", "_jp", "🇯🇵", " jp "),
            GeoLocationInfo("JP", "ژاپن", "🇯🇵", 35.6762f, 139.6503f)
        ),
        RegionRule(
            listOf("sweden", "stockholm", "arn", "se-", "_se", "🇸🇪", " se "),
            GeoLocationInfo("SE", "سوئد", "🇸🇪", 59.3293f, 18.0686f)
        ),
        RegionRule(
            listOf("switzerland", "zurich", "geneva", "zrh", "gva", "ch-", "_ch", "🇨🇭", " ch "),
            GeoLocationInfo("CH", "سوئیس", "🇨🇭", 47.3769f, 8.5417f)
        ),
        RegionRule(
            listOf("canada", "toronto", "montreal", "vancouver", "yyz", "yul", "yvr", "ca-", "_ca", "🇨🇦", " ca "),
            GeoLocationInfo("CA", "کانادا", "🇨🇦", 43.6532f, -79.3832f)
        ),
        RegionRule(
            listOf("poland", "warsaw", "waw", "pl-", "_pl", "🇵🇱", " pl "),
            GeoLocationInfo("PL", "لهستان", "🇵🇱", 52.2297f, 21.0122f)
        ),
        RegionRule(
            listOf("austria", "vienna", "vie", "at-", "_at", "🇦🇹", " at "),
            GeoLocationInfo("AT", "اتریش", "🇦🇹", 48.2082f, 16.3738f)
        ),
        RegionRule(
            listOf("uae", "dubai", "emirates", "dxb", "ae-", "_ae", "🇦🇪", " ae "),
            GeoLocationInfo("AE", "امارات", "🇦🇪", 25.2048f, 55.2708f)
        )
    )

    private val fallbackGeoPool = listOf(
        GeoLocationInfo("DE", "آلمان", "🇩🇪", 50.1109f, 8.6821f),
        GeoLocationInfo("NL", "هلند", "🇳🇱", 52.3676f, 4.9041f),
        GeoLocationInfo("FI", "فنلاند", "🇫🇮", 60.1699f, 24.9384f),
        GeoLocationInfo("FR", "فرانسه", "🇫🇷", 48.8566f, 2.3522f),
        GeoLocationInfo("GB", "انگلیس", "🇬🇧", 51.5072f, -0.1276f),
        GeoLocationInfo("SE", "سوئد", "🇸🇪", 59.3293f, 18.0686f),
        GeoLocationInfo("CH", "سوئیس", "🇨🇭", 47.3769f, 8.5417f),
        GeoLocationInfo("TR", "ترکیه", "🇹🇷", 41.0082f, 28.9784f),
        GeoLocationInfo("US", "آمریکا", "🇺🇸", 40.7128f, -74.0060f),
        GeoLocationInfo("SG", "سنگاپور", "🇸🇬", 1.3521f, 103.8198f)
    )

    fun geoForCountryCode(code: String): GeoLocationInfo {
        val upper = code.trim().uppercase()
        knownGeoLocations.firstOrNull { it.geo.countryCode.equals(upper, ignoreCase = true) }?.let {
            return it.geo
        }
        return knownGeoLocations.first().geo
    }

    fun parseSubscriptionPayload(
        payload: String,
        sourceRepo: String,
        maxLimit: Int = 45,
        filterPredicate: (V2RayConfig) -> Boolean = { true }
    ): List<V2RayConfig> {
        val trimmed = payload.trim()
        if (trimmed.isEmpty()) return emptyList()

        val decodedText = if (containsSchemeUris(trimmed)) {
            trimmed
        } else {
            decodeBase64Safe(trimmed).takeIf { containsSchemeUris(it) } ?: trimmed
        }

        val results = ArrayList<V2RayConfig>(maxLimit)
        val seenKeys = HashSet<String>()

        for (rawLine in decodedText.lineSequence()) {
            if (results.size >= maxLimit) break
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue
            val parsed = parseSingleUri(line, sourceRepo) ?: continue
            if (isValidHostAndPort(parsed.address, parsed.port) && filterPredicate(parsed)) {
                val key = "${parsed.protocol}:${parsed.address.lowercase()}:${parsed.port}:${parsed.uuidOrPassword}"
                if (seenKeys.add(key)) {
                    results.add(parsed)
                }
            }
        }

        return results
    }

    fun parseSingleUri(uriString: String, sourceRepo: String = "GitHub"): V2RayConfig? {
        val clean = uriString.trim()
        return try {
            when {
                clean.startsWith("aether://", ignoreCase = true) ->
                    parseCustomBypassUri(clean, V2RayProtocol.AETHER, sourceRepo.ifEmpty { "CluvexStudio/Aether" })
                clean.startsWith("serverless://", ignoreCase = true) ->
                    parseCustomBypassUri(clean, V2RayProtocol.SERVERLESS, sourceRepo.ifEmpty { "patterniha/Serverless-for-Iran" })
                clean.startsWith("snispoof://", ignoreCase = true) ->
                    parseCustomBypassUri(clean, V2RayProtocol.SNI_SPOOF, sourceRepo.ifEmpty { "patterniha/SNI-Spoofing" })
                clean.startsWith("vless://", ignoreCase = true) ->
                    parseVlessOrTrojan(clean, V2RayProtocol.VLESS, sourceRepo)
                clean.startsWith("trojan://", ignoreCase = true) ->
                    parseVlessOrTrojan(clean, V2RayProtocol.TROJAN, sourceRepo)
                clean.startsWith("vmess://", ignoreCase = true) ->
                    parseVmess(clean, sourceRepo)
                clean.startsWith("ss://", ignoreCase = true) ->
                    parseShadowsocks(clean, sourceRepo)
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parseCustomBypassUri(
        rawUri: String,
        protocol: V2RayProtocol,
        defaultRepo: String
    ): V2RayConfig? {
        val withoutScheme = rawUri.substringAfter("://")
        val fragment = urlDecodeSafe(withoutScheme.substringAfterLast("#", ""))
        val mainPart = withoutScheme.substringBefore("#")
        val queryPart = mainPart.substringAfter("?", "")
        val authorityPart = mainPart.substringBefore("?")

        val modeOrId = authorityPart.substringBefore("@", protocol.name.lowercase())
            .ifEmpty { protocol.name.lowercase() }
        val hostPortPart = if (authorityPart.contains("@")) authorityPart.substringAfter("@") else authorityPart
        val (host, port) = splitHostPort(hostPortPart) ?: return null
        val params = parseQueryParams(queryPart)

        val defaultSni = when (protocol) {
            V2RayProtocol.AETHER -> "engage.cloudflareclient.com"
            V2RayProtocol.SERVERLESS -> "cp.cloudflare.com"
            V2RayProtocol.SNI_SPOOF -> "speedtest.net"
            else -> host
        }
        val sni = params["sni"] ?: defaultSni
        val cc = params["cc"] ?: ""
        val geo = if (cc.isNotEmpty()) geoForCountryCode(cc) else detectGeoLocation(fragment, host, sni)

        val defaultNet = when (protocol) {
            V2RayProtocol.AETHER -> "masque-h2"
            V2RayProtocol.SERVERLESS -> "fragment-1-3"
            V2RayProtocol.SNI_SPOOF -> "sni-spoof"
            else -> "tcp"
        }

        return V2RayConfig(
            id = "${protocol.name}_${host}_${port}",
            rawUri = rawUri,
            protocol = protocol,
            remark = geo.countryNameFa,
            address = host,
            port = port,
            uuidOrPassword = modeOrId,
            network = params["net"] ?: defaultNet,
            tls = "tls",
            sni = sni,
            path = params["path"] ?: "/",
            hostHeader = params["host"] ?: sni,
            encryption = params["fragment"] ?: modeOrId,
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = defaultRepo
        )
    }

    private fun parseVlessOrTrojan(
        rawUri: String,
        protocol: V2RayProtocol,
        sourceRepo: String
    ): V2RayConfig? {
        val withoutScheme = rawUri.substringAfter("://")
        val fragment = urlDecodeSafe(withoutScheme.substringAfterLast("#", ""))
        val mainPart = withoutScheme.substringBefore("#")
        val queryPart = mainPart.substringAfter("?", "")
        val authorityPart = mainPart.substringBefore("?")

        val userInfo = authorityPart.substringBefore("@", "")
        val hostPortPart = authorityPart.substringAfter("@", "")
        if (userInfo.isEmpty() || hostPortPart.isEmpty()) return null

        val (host, port) = splitHostPort(hostPortPart) ?: return null
        val params = parseQueryParams(queryPart)

        val network = params["type"] ?: params["net"] ?: "tcp"
        val security = params["security"] ?: if (protocol == V2RayProtocol.TROJAN) "tls" else "none"
        val sni = params["sni"] ?: params["host"] ?: ""
        val path = params["path"] ?: params["serviceName"] ?: "/"
        val hostHeader = params["host"] ?: ""
        val encryption = params["encryption"] ?: "none"

        val geo = detectGeoLocation(fragment, host, sni)

        return V2RayConfig(
            id = "${protocol.name}_${host}_${port}",
            rawUri = rawUri,
            protocol = protocol,
            remark = geo.countryNameFa,
            address = host,
            port = port,
            uuidOrPassword = userInfo,
            network = network,
            tls = security,
            sni = sni,
            path = path,
            hostHeader = hostHeader,
            encryption = encryption,
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = sourceRepo
        )
    }

    private fun parseVmess(rawUri: String, sourceRepo: String): V2RayConfig? {
        val encoded = rawUri.substringAfter("vmess://").substringBefore("#").trim()
        val jsonStr = decodeBase64Safe(encoded)
        if (!jsonStr.startsWith("{")) return null

        val json = JSONObject(jsonStr)
        val address = json.optString("add", "").trim()
        val port = json.optString("port", "").toIntOrNull() ?: json.optInt("port", 0)
        val id = json.optString("id", "").trim()
        if (address.isEmpty() || port !in 1..65535 || id.isEmpty()) return null

        val ps = urlDecodeSafe(json.optString("ps", ""))
        val net = json.optString("net", "tcp").ifEmpty { "tcp" }
        val tls = json.optString("tls", "none").ifEmpty { "none" }
        val sni = json.optString("sni", json.optString("host", ""))
        val path = json.optString("path", "/")
        val hostHeader = json.optString("host", "")
        val scy = json.optString("scy", "auto")

        val geo = detectGeoLocation(ps, address, sni)

        return V2RayConfig(
            id = "VMESS_${address}_${port}",
            rawUri = rawUri,
            protocol = V2RayProtocol.VMESS,
            remark = geo.countryNameFa,
            address = address,
            port = port,
            uuidOrPassword = id,
            network = net,
            tls = tls,
            sni = sni,
            path = path,
            hostHeader = hostHeader,
            encryption = scy,
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = sourceRepo
        )
    }

    private fun parseShadowsocks(rawUri: String, sourceRepo: String): V2RayConfig? {
        val body = rawUri.substringAfter("ss://")
        val remarkRaw = urlDecodeSafe(body.substringAfter("#", ""))
        val main = body.substringBefore("#").substringBefore("?")

        val resolved = if (main.contains("@")) {
            val userEncoded = main.substringBefore("@")
            val hostPort = main.substringAfter("@")
            val decodedUser = decodeBase64Safe(userEncoded).ifEmpty { userEncoded }
            "$decodedUser@$hostPort"
        } else {
            decodeBase64Safe(main)
        }

        val userPart = resolved.substringBeforeLast("@", "")
        val hostPortPart = resolved.substringAfterLast("@", "")
        if (userPart.isEmpty() || hostPortPart.isEmpty()) return null

        val method = userPart.substringBefore(":", "chacha20-ietf-poly1305")
        val password = userPart.substringAfter(":", "")
        val (host, port) = splitHostPort(hostPortPart) ?: return null

        val geo = detectGeoLocation(remarkRaw, host, "")

        return V2RayConfig(
            id = "SS_${host}_${port}",
            rawUri = rawUri,
            protocol = V2RayProtocol.SHADOWSOCKS,
            remark = geo.countryNameFa,
            address = host,
            port = port,
            uuidOrPassword = password,
            network = "tcp",
            tls = "none",
            encryption = method,
            countryCode = geo.countryCode,
            countryNameFa = geo.countryNameFa,
            flagEmoji = geo.flagEmoji,
            latitude = geo.latitude,
            longitude = geo.longitude,
            sourceRepo = sourceRepo
        )
    }

    private fun splitHostPort(hostPort: String): Pair<String, Int>? {
        val trimmed = hostPort.trim().substringBefore("/")
        return if (trimmed.startsWith("[")) {
            val host = trimmed.substringAfter("[").substringBefore("]")
            val port = trimmed.substringAfter("]:", "").toIntOrNull() ?: return null
            if (host.isEmpty()) null else host to port
        } else {
            val host = trimmed.substringBeforeLast(":", "")
            val port = trimmed.substringAfterLast(":", "").toIntOrNull() ?: return null
            if (host.isEmpty()) null else host to port
        }
    }

    private fun parseQueryParams(query: String): Map<String, String> {
        if (query.isEmpty()) return emptyMap()
        return query.split("&").mapNotNull { pair ->
            val key = pair.substringBefore("=", "").trim()
            val value = urlDecodeSafe(pair.substringAfter("=", "").trim())
            if (key.isNotEmpty()) key to value else null
        }.toMap()
    }

    private fun containsSchemeUris(text: String): Boolean {
        return text.contains("aether://", ignoreCase = true) ||
            text.contains("serverless://", ignoreCase = true) ||
            text.contains("snispoof://", ignoreCase = true) ||
            text.contains("vless://", ignoreCase = true) ||
            text.contains("vmess://", ignoreCase = true) ||
            text.contains("trojan://", ignoreCase = true) ||
            text.contains("ss://", ignoreCase = true)
    }

    private fun isValidHostAndPort(host: String, port: Int): Boolean {
        if (port !in 1..65535) return false
        if (host.length < 3 || host.contains(" ") || host == "127.0.0.1" || host == "0.0.0.0" || host == "localhost") {
            return false
        }
        return true
    }

    private fun detectGeoLocation(remark: String, host: String, sni: String): GeoLocationInfo {
        val combined = " $remark $host $sni ".lowercase()
        for (rule in knownGeoLocations) {
            if (rule.keywords.any { combined.contains(it.lowercase()) }) {
                return rule.geo
            }
        }
        return when {
            host.endsWith(".de") -> knownGeoLocations[0].geo
            host.endsWith(".nl") -> knownGeoLocations[1].geo
            host.endsWith(".fi") -> knownGeoLocations[2].geo
            host.endsWith(".uk") -> knownGeoLocations[4].geo
            host.endsWith(".fr") -> knownGeoLocations[5].geo
            host.endsWith(".tr") -> knownGeoLocations[6].geo
            host.endsWith(".sg") -> knownGeoLocations[7].geo
            host.endsWith(".jp") -> knownGeoLocations[8].geo
            else -> {
                val index = abs(host.hashCode()) % fallbackGeoPool.size
                fallbackGeoPool[index]
            }
        }
    }

    private fun decodeBase64Safe(input: String): String {
        val sanitized = input.trim().replace("\n", "").replace("\r", "")
        if (sanitized.isEmpty()) return ""
        val flagsToTry = intArrayOf(
            Base64.DEFAULT,
            Base64.NO_WRAP,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        for (flag in flagsToTry) {
            try {
                val bytes = Base64.decode(sanitized, flag)
                val decoded = String(bytes, Charsets.UTF_8)
                if (decoded.isNotBlank()) return decoded
            } catch (_: Exception) {
            }
        }
        return ""
    }

    private fun urlDecodeSafe(input: String): String {
        if (input.isEmpty()) return ""
        return try {
            URLDecoder.decode(input, "UTF-8")
        } catch (_: Exception) {
            input
        }
    }
}
