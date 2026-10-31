package com.meh.vpn.model

import org.json.JSONArray
import org.json.JSONObject

enum class V2RayProtocol(val label: String) {
    VLESS("VLESS"),
    VMESS("VMess"),
    TROJAN("Trojan"),
    SHADOWSOCKS("SS")
}

enum class ConnectionStage {
    DISCONNECTED,
    FETCHING_SUBSCRIPTIONS,
    TESTING_SERVERS,
    CONNECTING,
    CONNECTED
}

data class GeoLocationInfo(
    val countryCode: String,
    val countryNameFa: String,
    val flagEmoji: String,
    val latitude: Float,
    val longitude: Float
)

data class GitHubSubscriptionSource(
    val id: String,
    val repoName: String,
    val repoUrl: String,
    val candidateRawUrls: List<String>,
    val isEnabled: Boolean = true
)

data class V2RayConfig(
    val id: String,
    val rawUri: String,
    val protocol: V2RayProtocol,
    val remark: String,
    val address: String,
    val port: Int,
    val uuidOrPassword: String,
    val network: String = "tcp",
    val tls: String = "none",
    val sni: String = "",
    val path: String = "/",
    val hostHeader: String = "",
    val encryption: String = "none",
    val countryCode: String = "DE",
    val countryNameFa: String = "آلمان",
    val flagEmoji: String = "🇩🇪",
    val latitude: Float = 50.1109f,
    val longitude: Float = 8.6821f,
    val sourceRepo: String = "GitHub",
    val pingMs: Int = -1
) {
    val isReachable: Boolean
        get() = pingMs in 1..4999

    val cleanTitle: String
        get() = "$flagEmoji $countryNameFa"

    /**
     * Generates a valid Xray / V2Ray-Core JSON configuration.
     */
    fun toV2RayCoreJson(): String {
        val root = JSONObject()

        root.put("log", JSONObject().apply {
            put("loglevel", "warning")
        })

        root.put("dns", JSONObject().apply {
            put("servers", JSONArray().apply {
                put("https://cloudflare-dns.com/dns-query")
                put("1.1.1.1")
                put("8.8.8.8")
            })
        })

        val inbounds = JSONArray()
        inbounds.put(JSONObject().apply {
            put("tag", "socks-in")
            put("port", 1819)
            put("listen", "127.0.0.1")
            put("protocol", "socks")
            put("settings", JSONObject().apply {
                put("auth", "noauth")
                put("udp", true)
            })
        })
        inbounds.put(JSONObject().apply {
            put("tag", "http-in")
            put("port", 10809)
            put("listen", "127.0.0.1")
            put("protocol", "http")
        })
        root.put("inbounds", inbounds)

        val outbounds = JSONArray()
        val proxyOutbound = JSONObject().apply {
            put("tag", "proxy")
            put("protocol", protocol.name.lowercase())

            val settings = JSONObject()
            when (protocol) {
                V2RayProtocol.VLESS -> {
                    val vnext = JSONArray()
                    vnext.put(JSONObject().apply {
                        put("address", address)
                        put("port", port)
                        put("users", JSONArray().apply {
                            put(JSONObject().apply {
                                put("id", uuidOrPassword)
                                put("encryption", encryption.ifEmpty { "none" })
                            })
                        })
                    })
                    settings.put("vnext", vnext)
                }
                V2RayProtocol.VMESS -> {
                    val vnext = JSONArray()
                    vnext.put(JSONObject().apply {
                        put("address", address)
                        put("port", port)
                        put("users", JSONArray().apply {
                            put(JSONObject().apply {
                                put("id", uuidOrPassword)
                                put("alterId", 0)
                                put("security", encryption.ifEmpty { "auto" })
                            })
                        })
                    })
                    settings.put("vnext", vnext)
                }
                V2RayProtocol.TROJAN -> {
                    val servers = JSONArray()
                    servers.put(JSONObject().apply {
                        put("address", address)
                        put("port", port)
                        put("password", uuidOrPassword)
                    })
                    settings.put("servers", servers)
                }
                V2RayProtocol.SHADOWSOCKS -> {
                    val servers = JSONArray()
                    servers.put(JSONObject().apply {
                        put("address", address)
                        put("port", port)
                        put("method", encryption.ifEmpty { "chacha20-ietf-poly1305" })
                        put("password", uuidOrPassword)
                    })
                    settings.put("servers", servers)
                }
            }
            put("settings", settings)

            put("streamSettings", JSONObject().apply {
                put("network", network)
                put("security", tls)
                if (tls == "tls" || tls == "reality") {
                    put("tlsSettings", JSONObject().apply {
                        put("serverName", sni.ifEmpty { address })
                        put("allowInsecure", false)
                    })
                }
                if (network == "ws") {
                    put("wsSettings", JSONObject().apply {
                        put("path", path.ifEmpty { "/" })
                        if (hostHeader.isNotEmpty()) {
                            put("headers", JSONObject().apply {
                                put("Host", hostHeader)
                            })
                        }
                    })
                } else if (network == "grpc") {
                    put("grpcSettings", JSONObject().apply {
                        put("serviceName", path.removePrefix("/"))
                    })
                }
            })
        }
        outbounds.put(proxyOutbound)
        outbounds.put(JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
        })
        root.put("outbounds", outbounds)

        return root.toString(2)
    }
}
