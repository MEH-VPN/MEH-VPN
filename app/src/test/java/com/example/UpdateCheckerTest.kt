package com.example

import com.example.data.AppUpdateInfo
import com.example.data.SemanticVersion
import com.example.data.UpdateChecker
import kotlinx.coroutines.test.runTest
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
    assertFalse(base > newerPatch)
  }

  @Test
  fun appUpdateInfo_defaultsAreValid() {
    val info =
      AppUpdateInfo(
        latestVersionName = "1.3.14",
      )
    assertEquals("1.3.14", info.latestVersionName)
    assertEquals(
      "https://github.com/MEH-VPN/MEH-VPN/releases/latest/download/MEH-VPN-latest.apk",
      info.downloadUrl,
    )
    assertEquals("https://t.me/MEH_VPN_channel", info.telegramUrl)
  }

  @Test
  fun check_detectsUpdateWhenRunning1_3_17_andRemoteIs1_3_18() = runTest {
    val checker = UpdateChecker()
    val update = checker.check(currentVersionRaw = "1.3.17")
    assertNotNull("Expected update to be found for 1.3.17", update)
    assertEquals("1.3.18", update?.latestVersionName)
  }

  @Test
  fun check_returnsNullWhenRunningLatestVersion() = runTest {
    val checker = UpdateChecker()
    val update = checker.check(currentVersionRaw = "1.3.18")
    assertNull("Expected null when already running latest version 1.3.18", update)
  }
}
