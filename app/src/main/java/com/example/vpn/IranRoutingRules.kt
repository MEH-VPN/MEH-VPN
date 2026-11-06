package com.example.vpn

import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Direct Routing (Split-Tunneling) Engine for Iranian IPs and Domestic Domains:
 * Ensures Iranian banking apps (Shaparak, BMI, Mellat, Blu, Saman, Pasargad, etc.), government
 * portals (`.ir`), and domestic platforms (Digikala, Snapp, Divar, Aparat, Torob, Filimo, etc.)
 * bypass the remote V2Ray tunnel and connect directly via a `VpnService.protect()`ed socket.
 */
object IranRoutingRules {

  /**
   * Non-`.ir` domestic Iranian domains (e.g. `.com` / `.org` / `.ai` services hosted inside Iran
   * that block foreign VPN IPs or require domestic direct routing).
   */
  private val DOMESTIC_NON_IR_DOMAINS =
    setOf(
      "digikala.com",
      "digikalajet.com",
      "digistyle.com",
      "digipay.info",
      "mydigipay.com",
      "snapp.cab",
      "snapp.market",
      "snapp.doctor",
      "snapp.express",
      "snappfood.com",
      "tapsi.cab",
      "aparat.com",
      "filimo.com",
      "telewebion.com",
      "torob.com",
      "emalls.me",
      "zarinpal.com",
      "zibal.io",
      "payping.io",
      "idpay.ir",
      "nextpay.org",
      "shaparak.com",
      "ebanksepah.com",
      "parsian-bank.com",
      "bpi.ir",
      "tejaratbank.com",
      "mellatbank.com",
      "sb24.com",
      "bankmellat.ir",
      "blubank.com",
      "nobitex.net",
      "wallex.ir",
      "ramzinex.com",
      "bitpin.org",
      "tabdeal.org",
      "bale.ai",
      "eitaa.com",
      "gap.im",
      "igap.net",
      "soroush-app.me",
      "neshan.org",
      "cafebazaar.org",
      "myket.ir",
      "arvancloud.com",
      "abrnoc.com",
      "parspack.com",
      "iranecar.com",
      "flytoday.ir",
      "alibaba.ir",
      "mrbilit.com",
      "snapptrip.com",
      "varzesh3.com",
      "zoomit.ir",
      "digiato.com",
      "tarafdari.com",
      "ninisite.com",
      "khabaronline.ir",
      "isna.ir",
      "irna.ir",
      "farsnews.com",
      "tasnimnews.com",
      "mehrnews.com",
    )

  private data class CidrRange(
    val networkUnsigned: Long,
    val maskUnsigned: Long,
  ) {
    fun contains(ipUnsigned: Long): Boolean {
      return (ipUnsigned and maskUnsigned) == networkUnsigned
    }
  }

  /**
   * Major Iranian IPv4 CIDR allocations (TCI, MCI, Irancell, Shatel, Asiatech, ArvanCloud,
   * Afranet, ParsOnline, Respina, MobinNet, Shaparak/CBI, IPM).
   */
  private val IRAN_IPV4_CIDRS: List<CidrRange> =
    listOf(
      "2.144.0.0/14",
      "2.176.0.0/12",
      "5.22.0.0/17",
      "5.52.0.0/16",
      "5.106.0.0/16",
      "5.112.0.0/13",
      "5.120.0.0/13",
      "5.160.0.0/14",
      "5.190.0.0/16",
      "5.200.0.0/14",
      "5.208.0.0/13",
      "31.2.128.0/17",
      "31.24.200.0/21",
      "31.40.0.0/16",
      "31.56.0.0/14",
      "37.32.0.0/16",
      "37.98.0.0/16",
      "37.137.0.0/16",
      "37.156.0.0/16",
      "37.254.0.0/15",
      "46.100.0.0/15",
      "46.143.0.0/16",
      "46.209.0.0/16",
      "46.224.0.0/15",
      "78.38.0.0/15",
      "78.157.32.0/19",
      "79.127.0.0/17",
      "79.175.128.0/18",
      "80.191.0.0/16",
      "81.91.128.0/18",
      "82.99.192.0/18",
      "85.15.0.0/18",
      "85.133.128.0/17",
      "85.185.0.0/16",
      "89.165.0.0/17",
      "89.196.0.0/16",
      "91.98.0.0/15",
      "91.251.0.0/16",
      "92.50.0.0/18",
      "93.110.0.0/15",
      "93.118.64.0/18",
      "94.182.0.0/15",
      "95.38.0.0/16",
      "95.80.128.0/18",
      "109.125.128.0/18",
      "109.162.128.0/17",
      "151.232.0.0/13",
      "164.138.128.0/18",
      "176.65.192.0/18",
      "178.131.0.0/16",
      "178.252.128.0/17",
      "185.4.28.0/22",
      "185.8.172.0/22",
      "185.88.152.0/22",
      "185.105.236.0/22",
      "185.143.232.0/22",
      "185.166.104.0/22",
      "188.158.0.0/15",
      "188.208.0.0/14",
      "194.225.0.0/16",
      "217.218.0.0/15",
    ).mapNotNull { parseCidr(it) }

  private fun parseCidr(cidr: String): CidrRange? {
    val slashIdx = cidr.indexOf('/')
    if (slashIdx <= 0) return null
    val ipPart = cidr.substring(0, slashIdx)
    val prefixLen = cidr.substring(slashIdx + 1).toIntOrNull() ?: return null
    if (prefixLen !in 1..32) return null
    val ipLong = ipv4StringToUnsignedLong(ipPart) ?: return null
    val mask = (0xFFFFFFFFL shl (32 - prefixLen)) and 0xFFFFFFFFL
    return CidrRange(networkUnsigned = ipLong and mask, maskUnsigned = mask)
  }

  private fun ipv4StringToUnsignedLong(host: String): Long? {
    val bytes = V2RayOutboundClient.parseIpv4Bytes(host) ?: return null
    return ((bytes[0].toLong() and 0xFFL) shl 24) or
      ((bytes[1].toLong() and 0xFFL) shl 16) or
      ((bytes[2].toLong() and 0xFFL) shl 8) or
      (bytes[3].toLong() and 0xFFL)
  }

  /**
   * Returns true if [domain] is an Iranian domain (`.ir`, `*.ir`, Shaparak, or a known domestic service).
   */
  fun isIranianDomain(domain: String?): Boolean {
    if (domain.isNullOrBlank()) return false
    val clean = domain.trim().trimEnd('.').lowercase()
    if (clean.isEmpty() || V2RayOutboundClient.parseIpv4Bytes(clean) != null) return false

    if (clean.endsWith(".ir") || clean == "ir") {
      return true
    }

    if (clean in DOMESTIC_NON_IR_DOMAINS) {
      return true
    }

    for (domestic in DOMESTIC_NON_IR_DOMAINS) {
      if (clean.endsWith(".$domestic")) {
        return true
      }
    }
    return false
  }

  /**
   * Returns true if [ipv4] belongs to an Iranian IPv4 CIDR block.
   */
  fun isIranianIpv4(ipv4: String?): Boolean {
    if (ipv4.isNullOrBlank()) return false
    val ipLong = ipv4StringToUnsignedLong(ipv4.trim()) ?: return false
    for (cidr in IRAN_IPV4_CIDRS) {
      if (cidr.contains(ipLong)) return true
    }
    return false
  }

  /**
   * Returns true if either the target hostname or the target IPv4 is an Iranian destination
   * that should bypass the V2Ray tunnel.
   */
  fun isIranianDestination(effectiveHost: String?, rawTargetHost: String? = null): Boolean {
    if (isIranianDomain(effectiveHost) || isIranianIpv4(effectiveHost)) return true
    if (isIranianDomain(rawTargetHost) || isIranianIpv4(rawTargetHost)) return true
    return false
  }

  /**
   * Resolves an Iranian domain directly via local/system DNS to a real routable IPv4 address.
   */
  fun resolveIranianDomainDirectIpv4(domain: String): ByteArray? {
    val clean = domain.trim().trimEnd('.')
    if (clean.isEmpty()) return null
    V2RayOutboundClient.parseIpv4Bytes(clean)?.let { return it }
    return try {
      val addresses = InetAddress.getAllByName(clean)
      for (addr in addresses) {
        if (addr is Inet4Address) {
          val bytes = addr.address
          if (bytes != null && bytes.size == 4 && V2RayOutboundClient.isPublicRoutableIpv4(bytes)) {
            return bytes
          }
        }
      }
      null
    } catch (_: Exception) {
      null
    }
  }

  /**
   * Opens a direct `VpnService.protect()`ed TCP connection to an Iranian host/IP,
   * bypassing the V2Ray tunnel for maximum speed and zero foreign-IP banking blocks.
   */
  fun openDirectProtectedTunnel(
    targetHost: String,
    targetPort: Int,
    timeoutMs: Int = 5000,
    protector: (Socket) -> Boolean,
    fallbackIpv4: String? = null,
  ): V2RayOutboundClient.TunnelConnection {
    val rawSocket = Socket()
    try {
      try {
        rawSocket.reuseAddress
      } catch (_: Exception) {}
      protector(rawSocket)
      rawSocket.tcpNoDelay = true
      rawSocket.keepAlive = true
      rawSocket.soTimeout = timeoutMs

      val connectAddress: InetAddress =
        V2RayOutboundClient.parseIpv4Bytes(targetHost)?.let { InetAddress.getByAddress(it) }
          ?: fallbackIpv4
            ?.takeIf { it != targetHost }
            ?.let { V2RayOutboundClient.parseIpv4Bytes(it) }
            ?.let { InetAddress.getByAddress(it) }
          ?: resolveIranianDomainDirectIpv4(targetHost)?.let { InetAddress.getByAddress(it) }
          ?: InetAddress.getByName(targetHost)

      rawSocket.connect(InetSocketAddress(connectAddress, targetPort), timeoutMs)
      MehDiag.recordIranDirectBypass()
      return V2RayOutboundClient.TunnelConnection(
        underlyingSocket = rawSocket,
        inputStream = rawSocket.getInputStream(),
        outputStream = rawSocket.getOutputStream(),
        tlsSocket = null,
      )
    } catch (e: Exception) {
      try {
        rawSocket.close()
      } catch (_: Exception) {}
      throw e
    }
  }
}
