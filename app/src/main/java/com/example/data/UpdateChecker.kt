package com.example.data

import com.example.BuildConfig
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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
 * Lightweight, resilient, zero-rate-limit update checker.
 *
 * Discovers the latest version across multiple resilient endpoints:
 * 1. jsDelivr Package API: automatically tracks GitHub tags via CDN (unblocked in Iran, 0 rate limit).
 * 2. GitHub 302 release redirect: checks HTTP Location header on /releases/latest (0 rate limit).
 * 3. Static version.json: served via jsDelivr CDN and GitHub raw.
 *
 * Compares the highest discovered version against the running app version.
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
    private const val JSDELIVR_PACKAGE_API =
      "https://data.jsdelivr.com/v1/package/gh/MEH-VPN/MEH-VPN"
    private const val GITHUB_LATEST_RELEASE_URL =
      "https://github.com/MEH-VPN/MEH-VPN/releases/latest"
    private const val CDN_VERSION_JSON =
      "https://cdn.jsdelivr.net/gh/MEH-VPN/MEH-VPN@main/version.json"
    private const val RAW_VERSION_JSON =
      "https://raw.githubusercontent.com/MEH-VPN/MEH-VPN/main/version.json"
  }

  suspend fun check(currentVersionRaw: String = BuildConfig.VERSION_NAME): AppUpdateInfo? =
    withContext(ioDispatcher) {
      runCatching {
        val currentVersion = SemanticVersion.parse(currentVersionRaw) ?: SemanticVersion(1, 3, 13)

        // Query available zero-rate-limit sources concurrently
        coroutineScope {
          val jsdelivrDeferred = async { fetchTagFromJsdelivrPackage() }
          val githubDeferred = async { fetchTagFromGithubRedirect() }
          val jsonDeferred = async { fetchFromJson(CDN_VERSION_JSON) ?: fetchFromJson(RAW_VERSION_JSON) }

          val jsdelivrTag = jsdelivrDeferred.await()
          val githubTag = githubDeferred.await()
          val jsonInfo = jsonDeferred.await()

          val jsdelivrSemver = SemanticVersion.parse(jsdelivrTag)
          val githubSemver = SemanticVersion.parse(githubTag)
          val jsonSemver = SemanticVersion.parse(jsonInfo?.latestVersionName)

          // Determine the highest available remote version among all successful sources
          var highestVersion: SemanticVersion? = null
          var candidateVersionName: String = ""

          if (jsdelivrSemver != null && (highestVersion == null || jsdelivrSemver > highestVersion)) {
            highestVersion = jsdelivrSemver
            candidateVersionName = jsdelivrTag!!.trim().removePrefix("v").removePrefix("V")
          }
          if (githubSemver != null && (highestVersion == null || githubSemver > highestVersion)) {
            highestVersion = githubSemver
            candidateVersionName = githubTag!!.trim().removePrefix("v").removePrefix("V")
          }
          if (jsonSemver != null && (highestVersion == null || jsonSemver > highestVersion)) {
            highestVersion = jsonSemver
            candidateVersionName = jsonInfo!!.latestVersionName.trim().removePrefix("v").removePrefix("V")
          }

          if (highestVersion != null && highestVersion > currentVersion) {
            return@coroutineScope AppUpdateInfo(
              latestVersionName = candidateVersionName,
              latestVersionCode = jsonInfo?.latestVersionCode ?: 0,
              downloadUrl = jsonInfo?.downloadUrl ?: AppUpdateInfo.DEFAULT_GITHUB_APK_URL,
              telegramUrl = jsonInfo?.telegramUrl ?: AppUpdateInfo.DEFAULT_TELEGRAM_URL,
            )
          }

          null
        }
      }.getOrNull()
    }

  private fun fetchTagFromJsdelivrPackage(): String? {
    return runCatching {
      val req = Request.Builder().url(JSDELIVR_PACKAGE_API).build()
      httpClient.newCall(req).execute().use { response ->
        if (!response.isSuccessful) return null
        val bodyStr = response.body?.string() ?: return null
        val json = JSONObject(bodyStr)
        val versions = json.optJSONArray("versions") ?: return null
        if (versions.length() == 0) return null
        versions.optString(0, "").ifBlank { null }
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
}
