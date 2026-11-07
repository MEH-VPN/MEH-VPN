package com.example.data

import com.example.BuildConfig
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

/**
 * Robust semantic version parser and comparator.
 * Parses version strings such as "1.3.13", "v1.3.14", "MEH v1.3.14", "1.3.14-beta", etc.
 */
data class SemanticVersion(
  val major: Int = 0,
  val minor: Int = 0,
  val patch: Int = 0,
  val build: Int = 0,
) : Comparable<SemanticVersion> {

  override fun compareTo(other: SemanticVersion): Int {
    if (major != other.major) return major.compareTo(other.major)
    if (minor != other.minor) return minor.compareTo(other.minor)
    if (patch != other.patch) return patch.compareTo(other.patch)
    return build.compareTo(other.build)
  }

  companion object {
    fun parse(raw: String?): SemanticVersion? {
      if (raw.isNullOrBlank()) return null
      val cleaned =
        raw.trim()
          .removePrefix("v")
          .removePrefix("V")
          .removePrefix("MEH-")
          .removePrefix("MEH v")
          .removePrefix("MEH ")
          .split("-")[0]
          .split("+")[0]
          .trim()

      val parts = cleaned.split(".").mapNotNull { it.toIntOrNull() }
      if (parts.isEmpty()) return null
      return SemanticVersion(
        major = parts.getOrElse(0) { 0 },
        minor = parts.getOrElse(1) { 0 },
        patch = parts.getOrElse(2) { 0 },
        build = parts.getOrElse(3) { 0 },
      )
    }
  }
}

/**
 * Metadata container for an available app update.
 */
data class AppUpdateInfo(
  val latestVersionName: String,
  val latestVersionCode: Int = 0,
  val downloadUrl: String = DEFAULT_GITHUB_APK_URL,
  val telegramUrl: String = DEFAULT_TELEGRAM_URL,
) {
  companion object {
    const val DEFAULT_GITHUB_APK_URL =
      "https://github.com/MEH-VPN/MEH-VPN/releases/latest/download/MEH-VPN-latest.apk"
    const val DEFAULT_TELEGRAM_URL = "https://t.me/MEH_VPN_channel"
  }
}

/**
 * Lightweight, zero-rate-limit update checker.
 * Checks CDN/Raw version.json first, with safe fallback to GitHub 302 release redirect.
 */
class UpdateChecker(
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
  private val httpClient: OkHttpClient =
    OkHttpClient.Builder()
      .connectTimeout(5, TimeUnit.SECONDS)
      .readTimeout(5, TimeUnit.SECONDS)
      .followRedirects(false)
      .build(),
) {

  companion object {
    private const val CDN_VERSION_JSON =
      "https://cdn.jsdelivr.net/gh/MEH-VPN/MEH-VPN@main/version.json"
    private const val RAW_VERSION_JSON =
      "https://raw.githubusercontent.com/MEH-VPN/MEH-VPN/main/version.json"
    private const val GITHUB_LATEST_RELEASE_URL =
      "https://github.com/MEH-VPN/MEH-VPN/releases/latest"
  }

  suspend fun check(currentVersionRaw: String = BuildConfig.VERSION_NAME): AppUpdateInfo? =
    withContext(ioDispatcher) {
      runCatching {
        val currentVersion = SemanticVersion.parse(currentVersionRaw) ?: SemanticVersion(1, 3, 13)

        // 1. Try reading version.json from CDN or GitHub Raw
        val fromJson = fetchFromJson(CDN_VERSION_JSON) ?: fetchFromJson(RAW_VERSION_JSON)
        if (fromJson != null) {
          val remote = SemanticVersion.parse(fromJson.latestVersionName)
          if (remote != null && remote > currentVersion) {
            return@withContext fromJson
          }
          return@withContext null
        }

        // 2. Fallback: check 302 redirect from GitHub releases/latest (Zero rate-limit)
        val tagFromRedirect = fetchTagFromGithubRedirect()
        if (tagFromRedirect != null) {
          val remote = SemanticVersion.parse(tagFromRedirect)
          if (remote != null && remote > currentVersion) {
            return@withContext AppUpdateInfo(
              latestVersionName = tagFromRedirect,
              downloadUrl = AppUpdateInfo.DEFAULT_GITHUB_APK_URL,
              telegramUrl = AppUpdateInfo.DEFAULT_TELEGRAM_URL,
            )
          }
        }

        null
      }.getOrNull()
    }

  private fun fetchFromJson(url: String): AppUpdateInfo? {
    return runCatching {
      val req = Request.Builder().url(url).build()
      httpClient.newCall(req).execute().use { response ->
        if (!response.isSuccessful) return null
        val bodyStr = response.body?.string() ?: return null
        val json = JSONObject(bodyStr)
        val versionName = json.optString("latest_version_name", "")
        if (versionName.isBlank()) return null
        AppUpdateInfo(
          latestVersionName = versionName,
          latestVersionCode = json.optInt("latest_version_code", 0),
          downloadUrl = json.optString("download_url", AppUpdateInfo.DEFAULT_GITHUB_APK_URL),
          telegramUrl = json.optString("telegram_url", AppUpdateInfo.DEFAULT_TELEGRAM_URL),
        )
      }
    }.getOrNull()
  }

  private fun fetchTagFromGithubRedirect(): String? {
    return runCatching {
      val req = Request.Builder().url(GITHUB_LATEST_RELEASE_URL).head().build()
      httpClient.newCall(req).execute().use { response ->
        val location = response.header("Location") ?: return null
        val tag =
          location.substringAfterLast("/tag/", "").ifBlank {
            location.substringAfterLast("/")
          }
        tag.ifBlank { null }
      }
    }.getOrNull()
  }
}
