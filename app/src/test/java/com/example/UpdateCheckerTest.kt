package com.example

import com.example.data.AppUpdateInfo
import com.example.data.SemanticVersion
import com.example.data.UpdateChecker
import kotlinx.coroutines.test.runTest
import okhttp3.Headers
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {

  @Test
  fun parseSemanticVersion_handlesCleanAndPrefixedFormats() {
    val v1 = SemanticVersion.parse("1.3.13")
    assertNotNull(v1)
    assertEquals(1, v1?.major)
    assertEquals(3, v1?.minor)
    assertEquals(13, v1?.patch)

    val v2 = SemanticVersion.parse("v1.4.0")
    assertNotNull(v2)
    assertEquals(1, v2?.major)
    assertEquals(4, v2?.minor)
    assertEquals(0, v2?.patch)

    val v3 = SemanticVersion.parse("MEH v1.3.14")
    assertNotNull(v3)
    assertEquals(1, v3?.major)
    assertEquals(3, v3?.minor)
    assertEquals(14, v3?.patch)

    val v4 = SemanticVersion.parse("v1.3.15-test+build100")
    assertNotNull(v4)
    assertEquals(1, v4?.major)
    assertEquals(3, v4?.minor)
    assertEquals(15, v4?.patch)
  }

  @Test
  fun parseSemanticVersion_handlesInvalidInputs() {
    assertNull(SemanticVersion.parse(null))
    assertNull(SemanticVersion.parse(""))
    assertNull(SemanticVersion.parse("   "))
    assertNull(SemanticVersion.parse("unknown-text"))
  }

  @Test
  fun semanticVersion_comparesVersionsCorrectly() {
    val base = SemanticVersion.parse("1.3.13")!!
    val newerPatch = SemanticVersion.parse("1.3.14")!!
    val newerMinor = SemanticVersion.parse("1.4.0")!!
    val newerMajor = SemanticVersion.parse("2.0.0")!!
    val same = SemanticVersion.parse("v1.3.13")!!
    val older = SemanticVersion.parse("1.3.12")!!

    assertTrue(newerPatch > base)
    assertTrue(newerMinor > base)
    assertTrue(newerMajor > base)
    assertEquals(0, base.compareTo(same))
    assertTrue(older < base)
  }

  @Test
  fun isNewerVersionAvailable_returnsFalseForSameVersion() {
    val current = SemanticVersion.parse("1.3.18")!!
    val latest = SemanticVersion.parse("v1.3.18")!!
    assertFalse(current < latest)
  }

  /**
   * Fake HTTP client that answers the three update sources with canned
   * responses for a fixed "remote latest" of 1.3.18, so the check() tests
   * never touch the live network and never go stale when a new version ships.
   */
  private fun fakeClientForRemote1_3_18(): OkHttpClient {
    val interceptor = Interceptor { chain ->
      val url = chain.request().url.toString()
      val headers = Headers.Builder()
      val (code, body) = when {
        url.contains("data.jsdelivr.com") ->
          200 to """{"versions":["v1.3.18"]}"""
        url.contains("releases/latest") -> {
          headers.add("Location", "https://github.com/MEH-VPN/MEH-VPN/releases/tag/v1.3.18")
          302 to ""
        }
        url.contains("version.json") ->
          200 to """{"latest_version_name":"1.3.18","latest_version_code":10318,"download_url":"https://github.com/MEH-VPN/MEH-VPN/releases/latest/download/MEH-VPN-latest.apk","telegram_url":"https://t.me/MEH_VPN_channel"}"""
        else -> 404 to ""
      }
      Response.Builder()
        .request(chain.request())
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message("OK")
        .headers(headers.build())
        .body(body.toResponseBody("application/json".toMediaType()))
        .build()
    }
    return OkHttpClient.Builder().addInterceptor(interceptor).build()
  }

  @Test
  fun check_detectsUpdateWhenRunning1_3_17_andRemoteIs1_3_18() = runTest {
    val checker = UpdateChecker(httpClient = fakeClientForRemote1_3_18())
    val update = checker.check("1.3.17", 10317)
    assertNotNull(update)
    assertEquals("1.3.18", update?.versionName)
    assertEquals(10318, update?.versionCode)
    assertEquals("https://github.com/MEH-VPN/MEH-VPN/releases/latest/download/MEH-VPN-latest.apk", update?.downloadUrl)
    assertEquals("https://t.me/MEH_VPN_channel", update?.telegramUrl)
  }

  @Test
  fun check_returnsNullWhenRunningLatestVersion() = runTest {
    val checker = UpdateChecker(httpClient = fakeClientForRemote1_3_18())
    val update = checker.check("1.3.18", 10318)
    assertNull(update)
  }
}
