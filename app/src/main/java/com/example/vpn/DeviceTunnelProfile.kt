package com.example.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Concrete TUN + DNS architecture profiles supported by MEH using the already-bundled
 * `libXray` + `hev-socks5-tunnel` native libraries.
 */
enum class TunnelProfile(
  val id: String,
  val titleFa: String,
  val shortBadgeFa: String,
  val descriptionFa: String,
) {
  /**
   * v2rayNG-style standard mode: `hev-socks5-tunnel` WITHOUT `mapdns` (no Fake-IPs).
   * Android sends real DNS queries (`1.1.1.1` / `8.8.8.8`) into TUN -> `hev-socks5-tunnel` ->
   * Xray `socks-in` -> Xray `dns-out` (`tcp://1.1.1.1` over proxy).
   *
   * Zero CGNAT `100.64.0.0/10` collision on Hamrah-e Aval (MCI) and fully compatible with
   * Android 9 (Pie) default Private DNS "Automatic" (`1.1.1.1:853` routes through proxy).
   */
  HEV_DIRECT_DNS(
    id = "hev_direct_dns",
    titleFa = "استاندارد v2rayNG (DNS واقعی)",
    shortBadgeFa = "DNS واقعی",
    descriptionFa = "بدون IP جعلی؛ بهترین سازگاری با اندروید ۹، سامسونگ و همراه اول (بدون تداخل CGNAT)",
  ),

  /**
   * `hev-socks5-tunnel` WITH `mapdns` mapped onto RFC 2544 benchmarking space (`198.18.0.0/15`):
   * TUN `198.18.0.1/30`, DNS `198.18.0.2`, Fake-IP pool `198.19.0.0/16`.
   * Completely avoids `100.64.0.0/10` (MCI CGNAT), `10.0.0.0/8` (direct LAN rule), and `240.0.0.0/4`.
   */
  HEV_MAPDNS_SAFE(
    id = "hev_mapdns_safe",
    titleFa = "سریع (MapDNS ایمن 198.18)",
    shortBadgeFa = "MapDNS 198.18",
    descriptionFa = "ترجمه فوری دامنه با رنج ایمن 198.18.0.0/15 (بدون تداخل با شبکه موبایل)",
  ),

  /**
   * Native Go `libXray` built-in `proxy/tun` (`setTunFd`) with real DNS (`1.1.1.1` / `8.8.8.8`),
   * bypassing `hev-socks5-tunnel` completely for devices whose kernel/ROM conflicts with hevtunnel.
   */
  NATIVE_XRAY_TUN(
    id = "native_xray_tun",
    titleFa = "تونل بومی Xray (بدون Hev)",
    shortBadgeFa = "Xray بومی",
    descriptionFa = "اتصال مستقیم هسته Xray به TUN سیستم؛ مناسب گوشی‌هایی که با Hev ناسازگارند",
  );

  companion object {
    fun fromId(id: String?): TunnelProfile? = entries.firstOrNull { it.id == id }
  }
}

/** User-selectable mode: either automatic per-device/network calibration or a locked profile. */
enum class TunnelModePreference(
  val id: String,
  val titleFa: String,
) {
  AUTO("auto", "خودکار (بهینه‌سازی هوشمند دستگاه)"),
  HEV_DIRECT_DNS(TunnelProfile.HEV_DIRECT_DNS.id, TunnelProfile.HEV_DIRECT_DNS.titleFa),
  HEV_MAPDNS_SAFE(TunnelProfile.HEV_MAPDNS_SAFE.id, TunnelProfile.HEV_MAPDNS_SAFE.titleFa),
  NATIVE_XRAY_TUN(TunnelProfile.NATIVE_XRAY_TUN.id, TunnelProfile.NATIVE_XRAY_TUN.titleFa);

  fun toLockedProfileOrNull(): TunnelProfile? {
    return when (this) {
      AUTO -> null
      HEV_DIRECT_DNS -> TunnelProfile.HEV_DIRECT_DNS
      HEV_MAPDNS_SAFE -> TunnelProfile.HEV_MAPDNS_SAFE
      NATIVE_XRAY_TUN -> TunnelProfile.NATIVE_XRAY_TUN
    }
  }

  companion object {
    fun fromId(id: String?): TunnelModePreference =
      entries.firstOrNull { it.id == id } ?: AUTO
  }
}

data class DeviceCalibrationSnapshot(
  val sdkInt: Int,
  val androidRelease: String,
  val deviceModel: String,
  val transportLabel: String,
  val isCellular: Boolean,
  val isMetered: Boolean,
  val hasCgnat100Interface: Boolean,
  val hasCarrier10Interface: Boolean,
  val interfaceAddresses: List<String>,
  val linkDnsServers: List<String>,
  val privateDnsModeRaw: String,
  val privateDnsHostname: String?,
  val linkPrivateDnsActive: Boolean,
  val linkPrivateDnsServerName: String?,
  val recommendedProfile: TunnelProfile,
  val recommendationReasonFa: String,
  val recommendationReasonEn: String,
)

/**
 * Inspects device OS version, active physical network interfaces (CGNAT `100.64.0.0/10` detection),
 * and Android Private DNS state (including Android 9's default `opportunistic` / Automatic mode)
 * to automatically select and persist the optimal [TunnelProfile] for each user's device.
 */
object DeviceTunnelCalibrator {

  private const val PREFS_NAME = "meh_device_calibration_prefs"
  private const val KEY_SELECTED_MODE = "selected_tunnel_mode"
  private const val KEY_LAST_RECOMMENDED = "last_recommended_profile"
  private const val KEY_LAST_CALIBRATED_AT = "last_calibrated_at_ms"

  const val DIRECT_TUN_IPV4 = "10.10.14.1"
  const val DIRECT_DNS_PRIMARY = "1.1.1.1"
  const val DIRECT_DNS_SECONDARY = "8.8.8.8"

  const val SAFE_MAPDNS_TUN_IPV4 = "198.18.0.1"
  const val SAFE_MAPDNS_DNS_ADDR = "198.18.0.2"
  const val SAFE_MAPDNS_NETWORK = "198.19.0.0"
  const val SAFE_MAPDNS_NETMASK = "255.255.0.0"

  /** Pure deterministic helper for deciding the optimal tunnel profile for a device + network. */
  internal fun recommendProfile(
    sdkInt: Int,
    isCellular: Boolean,
    hasCgnat100Interface: Boolean,
    privateDnsModeRaw: String,
    linkPrivateDnsActive: Boolean,
  ): Triple<TunnelProfile, String, String> {
    val normalizedDnsMode = privateDnsModeRaw.trim().lowercase()
    val isOpportunisticOrImplicitPie =
      sdkInt == Build.VERSION_CODES.P &&
        (normalizedDnsMode.isEmpty() || normalizedDnsMode == "opportunistic" || linkPrivateDnsActive)

    return when {
      sdkInt <= Build.VERSION_CODES.P -> {
        Triple(
          TunnelProfile.HEV_DIRECT_DNS,
          "اندروید ۹ شناسایی شد؛ حالت DNS واقعی (استاندارد v2rayNG) برای سازگاری کامل با netd و Private DNS خودکار انتخاب شد.",
          "Android 9 (SDK $sdkInt, privateDns=$privateDnsModeRaw, cgnat100=$hasCgnat100Interface) -> HEV_DIRECT_DNS avoids netd opportunistic DoT deadlock and Fake-IP quirks.",
        )
      }
      hasCgnat100Interface -> {
        Triple(
          TunnelProfile.HEV_DIRECT_DNS,
          "شبکه موبایل CGNAT (رنج 100.64) شناسایی شد؛ حالت DNS واقعی بدون IP جعلی انتخاب شد.",
          "Carrier CGNAT 100.64.0.0/10 detected on active interface -> HEV_DIRECT_DNS avoids all Fake-IP/CGNAT conflicts.",
        )
      }
      isCellular -> {
        Triple(
          TunnelProfile.HEV_DIRECT_DNS,
          "اتصال دیتای موبایل فعال است؛ حالت استاندارد v2rayNG با DNS واقعی انتخاب شد.",
          "Cellular mobile data active -> HEV_DIRECT_DNS selected for maximum ISP & app compatibility.",
        )
      }
      isOpportunisticOrImplicitPie -> {
        Triple(
          TunnelProfile.HEV_DIRECT_DNS,
          "حالت خودکار Private DNS فعال است؛ DNS واقعی انتخاب شد.",
          "Opportunistic Private DNS detected -> HEV_DIRECT_DNS selected.",
        )
      }
      else -> {
        Triple(
          TunnelProfile.HEV_MAPDNS_SAFE,
          "وای‌فای روی اندروید جدید شناسایی شد؛ حالت MapDNS ایمن (198.18) برای سرعت بیشتر انتخاب شد.",
          "Wi-Fi on Android SDK $sdkInt without CGNAT -> HEV_MAPDNS_SAFE (198.18.0.0/15).",
        )
      }
    }
  }

  /** Returns true if [ipv4] lies in RFC 6598 CGNAT `100.64.0.0/10` (`100.64.0.0` .. `100.127.255.255`). */
  internal fun isCgnat100Address(ipv4: String): Boolean {
    val parts = ipv4.split(".")
    if (parts.size != 4) return false
    val o0 = parts[0].toIntOrNull() ?: return false
    val o1 = parts[1].toIntOrNull() ?: return false
    return o0 == 100 && o1 in 64..127
  }

  /** Inspects live device, network interfaces, and Private DNS settings without blocking network I/O. */
  fun inspectDeviceAndNetwork(context: Context): DeviceCalibrationSnapshot {
    val appCtx = context.applicationContext
    var isCellular = false
    var isWifi = false
    var isMetered = false
    val linkDnsServers = mutableListOf<String>()
    var linkPrivateDnsActive = false
    var linkPrivateDnsServerName: String? = null

    try {
      val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
      if (cm != null) {
        isMetered = cm.isActiveNetworkMetered
        val activeNet = cm.activeNetwork
        if (activeNet != null) {
          val caps = cm.getNetworkCapabilities(activeNet)
          if (caps != null) {
            isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
            isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
          }
          val lp = cm.getLinkProperties(activeNet)
          if (lp != null) {
            lp.dnsServers.forEach { addr ->
              addr.hostAddress?.let { linkDnsServers.add(it) }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              linkPrivateDnsActive = lp.isPrivateDnsActive
              linkPrivateDnsServerName = lp.privateDnsServerName
            }
          }
        }
      }
    } catch (_: Throwable) {}

    val interfaceAddresses = mutableListOf<String>()
    var hasCgnat100 = false
    var hasCarrier10 = false
    try {
      val ifaces = NetworkInterface.getNetworkInterfaces()
      while (ifaces != null && ifaces.hasMoreElements()) {
        val nif = ifaces.nextElement()
        val name = nif.name.orEmpty()
        if (nif.isLoopback || !nif.isUp || name.startsWith("tun")) continue
        val addrs = nif.inetAddresses
        while (addrs.hasMoreElements()) {
          val addr = addrs.nextElement()
          if (addr is Inet4Address && !addr.isLoopbackAddress) {
            val host = addr.hostAddress.orEmpty()
            if (host.isNotBlank()) {
              interfaceAddresses.add("$name:$host")
              if (isCgnat100Address(host)) hasCgnat100 = true
              if (host.startsWith("10.")) hasCarrier10 = true
            }
          }
        }
      }
    } catch (_: Throwable) {}

    var globalDnsMode = ""
    var globalDnsSpec: String? = null
    try {
      globalDnsMode =
        Settings.Global.getString(appCtx.contentResolver, "private_dns_mode").orEmpty()
      globalDnsSpec =
        Settings.Global.getString(appCtx.contentResolver, "private_dns_specifier")
          ?.trim()
          ?.takeIf { it.isNotEmpty() }
    } catch (_: Throwable) {}

    val transportLabel =
      when {
        isCellular -> "دیتای موبایل"
        isWifi -> "وای‌فای"
        else -> "شبکه فعال"
      }

    val (recommended, reasonFa, reasonEn) =
      recommendProfile(
        sdkInt = Build.VERSION.SDK_INT,
        isCellular = isCellular,
        hasCgnat100Interface = hasCgnat100,
        privateDnsModeRaw = globalDnsMode.ifBlank { "default" },
        linkPrivateDnsActive = linkPrivateDnsActive,
      )

    return DeviceCalibrationSnapshot(
      sdkInt = Build.VERSION.SDK_INT,
      androidRelease = Build.VERSION.RELEASE.orEmpty().ifBlank { "?" },
      deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
      transportLabel = transportLabel,
      isCellular = isCellular,
      isMetered = isMetered,
      hasCgnat100Interface = hasCgnat100,
      hasCarrier10Interface = hasCarrier10,
      interfaceAddresses = interfaceAddresses,
      linkDnsServers = linkDnsServers,
      privateDnsModeRaw = globalDnsMode.ifBlank { "default" },
      privateDnsHostname = globalDnsSpec ?: linkPrivateDnsServerName,
      linkPrivateDnsActive = linkPrivateDnsActive,
      linkPrivateDnsServerName = linkPrivateDnsServerName,
      recommendedProfile = recommended,
      recommendationReasonFa = reasonFa,
      recommendationReasonEn = reasonEn,
    )
  }

  /** Runs calibration, persists the recommended profile, and writes full telemetry to [MehFullLogger]. */
  fun runInitialCalibration(context: Context, trigger: String = "startup"): DeviceCalibrationSnapshot {
    val appCtx = context.applicationContext
    val snap = inspectDeviceAndNetwork(appCtx)
    val selectedMode = getSelectedMode(appCtx)
    val effective = selectedMode.toLockedProfileOrNull() ?: snap.recommendedProfile

    appCtx
      .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(KEY_LAST_RECOMMENDED, snap.recommendedProfile.id)
      .putLong(KEY_LAST_CALIBRATED_AT, System.currentTimeMillis())
      .apply()

    MehFullLogger.log(
      FullLogCategory.CALIBRATION,
      "Calibration($trigger) | device=${snap.deviceModel} Android ${snap.androidRelease} (SDK ${snap.sdkInt}) | " +
        "net=${snap.transportLabel} metered=${snap.isMetered} cgnat100=${snap.hasCgnat100Interface} " +
        "ifaces=[${snap.interfaceAddresses.joinToString(",")}] | " +
        "linkDns=[${snap.linkDnsServers.joinToString(",")}] | " +
        "privateDns=${snap.privateDnsModeRaw}(${snap.privateDnsHostname ?: "-"}, linkActive=${snap.linkPrivateDnsActive}) | " +
        "mode=${selectedMode.id} -> effective=${effective.id} (${snap.recommendationReasonEn})",
    )
    return snap
  }

  fun getSelectedMode(context: Context): TunnelModePreference {
    val raw =
      context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getString(KEY_SELECTED_MODE, TunnelModePreference.AUTO.id)
    return TunnelModePreference.fromId(raw)
  }

  fun setSelectedMode(context: Context, mode: TunnelModePreference) {
    val appCtx = context.applicationContext
    appCtx
      .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(KEY_SELECTED_MODE, mode.id)
      .apply()
    val effective = resolveEffectiveProfile(appCtx)
    MehFullLogger.log(
      FullLogCategory.CALIBRATION,
      "User selected tunnel mode=${mode.id} -> effective=${effective.id} (${effective.titleFa})",
    )
  }

  fun resolveEffectiveProfile(context: Context): TunnelProfile {
    val appCtx = context.applicationContext
    val selected = getSelectedMode(appCtx)
    selected.toLockedProfileOrNull()?.let { return it }
    val snap = inspectDeviceAndNetwork(appCtx)
    return snap.recommendedProfile
  }

  fun resetToAuto(context: Context) {
    setSelectedMode(context, TunnelModePreference.AUTO)
  }
}
