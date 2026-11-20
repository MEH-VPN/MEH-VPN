package com.example.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.provider.Settings

/**
 * Snapshot of the device's Android Private DNS (DNS-over-TLS) configuration.
 *
 * When a custom strict Private DNS hostname is configured (especially Iranian anti-sanction DNS
 * providers like Shecan/403/Electro/Radar), Android bypasses our TUN `mapdns` resolver, which can
 * cause filtered destinations to resolve to poisoned IPs or fail to bypass censorship.
 */
data class PrivateDnsStatus(
  val isStrictCustomActive: Boolean = false,
  val hostname: String? = null,
  val isLikelyIranianSanctionDns: Boolean = false,
)

object PrivateDnsDetector {

  private const val SETTING_PRIVATE_DNS_MODE = "private_dns_mode"
  private const val SETTING_PRIVATE_DNS_SPECIFIER = "private_dns_specifier"
  private const val MODE_HOSTNAME = "hostname"

  private val IRANIAN_DNS_KEYWORDS =
    listOf(
      "shecan",
      "403.online",
      "electro",
      "radar",
      "begzar",
      "bepass",
      "shelter",
      "hostiran",
      "shatel",
    )

  /**
   * Pure evaluation helper combining Android Global Settings and active [LinkProperties] signals.
   * Returns [PrivateDnsStatus.isStrictCustomActive] = true only when a custom strict Private DNS
   * hostname is active (Android's default "off" and "automatic/opportunistic" modes do not trigger
   * false alarms).
   */
  internal fun evaluate(
    globalMode: String?,
    globalSpecifier: String?,
    linkPrivateDnsActive: Boolean,
    linkPrivateDnsServerName: String?,
  ): PrivateDnsStatus {
    val cleanMode = globalMode?.trim()?.lowercase().orEmpty()
    val cleanSpecifier = globalSpecifier?.trim()?.takeIf { it.isNotEmpty() }
    val cleanLinkHost = linkPrivateDnsServerName?.trim()?.takeIf { it.isNotEmpty() }

    val isStrictFromSettings = cleanMode == MODE_HOSTNAME && cleanSpecifier != null
    val isStrictFromLink = linkPrivateDnsActive && cleanLinkHost != null
    val active = isStrictFromSettings || isStrictFromLink
    if (!active) {
      return PrivateDnsStatus(isStrictCustomActive = false)
    }

    val host = cleanLinkHost ?: cleanSpecifier
    val lowerHost = host?.lowercase().orEmpty()
    val isIranian =
      lowerHost.endsWith(".ir") || IRANIAN_DNS_KEYWORDS.any { keyword -> lowerHost.contains(keyword) }

    return PrivateDnsStatus(
      isStrictCustomActive = true,
      hostname = host,
      isLikelyIranianSanctionDns = isIranian,
    )
  }

  /** Reads the current device Private DNS state safely using existing `ACCESS_NETWORK_STATE`. */
  fun detect(context: Context): PrivateDnsStatus {
    val appCtx = context.applicationContext
    var globalMode: String? = null
    var globalSpecifier: String? = null
    try {
      globalMode = Settings.Global.getString(appCtx.contentResolver, SETTING_PRIVATE_DNS_MODE)
      globalSpecifier = Settings.Global.getString(appCtx.contentResolver, SETTING_PRIVATE_DNS_SPECIFIER)
    } catch (_: Throwable) {}

    var linkActive = false
    var linkHost: String? = null
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val lp = if (activeNetwork != null) cm.getLinkProperties(activeNetwork) else null
        if (lp != null) {
          linkActive = lp.isPrivateDnsActive
          linkHost = lp.privateDnsServerName
        }
      } catch (_: Throwable) {}
    }

    return evaluate(
      globalMode = globalMode,
      globalSpecifier = globalSpecifier,
      linkPrivateDnsActive = linkActive,
      linkPrivateDnsServerName = linkHost,
    )
  }

  /** Opens Android's Network & Internet settings screen where Private DNS can be toggled off. */
  fun openPrivateDnsSettings(context: Context) {
    val candidates =
      listOf(
        Intent(Settings.ACTION_WIRELESS_SETTINGS),
        Intent(Settings.ACTION_SETTINGS),
      )
    for (intent in candidates) {
      val started =
        runCatching {
          intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          context.startActivity(intent)
        }.isSuccess
      if (started) return
    }
  }
}
