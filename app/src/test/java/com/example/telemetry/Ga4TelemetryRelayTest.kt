package com.example.telemetry

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Ga4TelemetryRelayTest {

  private lateinit var context: Context

  @Before
  fun setUp() {
    context = ApplicationProvider.getApplicationContext()
    Ga4TelemetryRelay.clearQueueForTests(context)
    Ga4TelemetryRelay.relayUrlOverride = null
    Ga4TelemetryRelay.transportOverride = null
    Ga4TelemetryRelay.socksPortProvider = { 0 }
  }

  @After
  fun tearDown() {
    Ga4TelemetryRelay.clearQueueForTests(context)
    Ga4TelemetryRelay.relayUrlOverride = null
    Ga4TelemetryRelay.transportOverride = null
    Ga4TelemetryRelay.socksPortProvider = { 0 }
  }

  @Test
  fun normalizeAppInstanceId_producesValid32CharLowercaseHex() {
    val valid = "0123456789abcdef0123456789abcdef"
    assertEquals(valid, Ga4TelemetryRelay.normalizeAppInstanceId(valid))
    assertEquals(
      valid,
      Ga4TelemetryRelay.normalizeAppInstanceId("01234567-89AB-CDEF-0123-456789ABCDEF"),
    )

    val generated = Ga4TelemetryRelay.normalizeAppInstanceId("invalid-id")
    assertTrue(
      "Must always generate a strict 32-char hex Firebase app_instance_id",
      Regex("^[0-9a-f]{32}$").matches(generated),
    )
  }

  @Test
  fun buildMeasurementPayload_includesFirebaseRealtimeEngagementAndTypedParams() {
    val nowMs = 1_760_000_000_000L
    val oldEventMs = nowMs - 120_000L // 2 minutes earlier (offline buffered)
    val payloadStr =
      Ga4TelemetryRelay.buildMeasurementPayload(
        appInstanceId = "aabbccddeeff00112233445566778899",
        sessionId = 1_760_000_000L,
        appVersion = "1.3.20",
        events =
          listOf(
            Ga4TelemetryRelay.QueuedEvent(
              name = "vpn_connected",
              params =
                mapOf(
                  "protocol" to "V2Ray:VLESS",
                  "latency_ms" to 145L,
                  "session_number" to 3,
                ),
              timestampMs = oldEventMs,
            )
          ),
        nowMs = nowMs,
      )

    val root = JSONObject(payloadStr)
    assertEquals("aabbccddeeff00112233445566778899", root.getString("app_instance_id"))
    assertEquals(oldEventMs * 1_000L, root.getLong("timestamp_micros"))
    assertEquals(
      "1.3.20",
      root.getJSONObject("user_properties").getJSONObject("app_ver").getString("value"),
    )

    val events = root.getJSONArray("events")
    assertEquals(1, events.length())
    val ev = events.getJSONObject(0)
    assertEquals("vpn_connected", ev.getString("name"))
    val params = ev.getJSONObject("params")
    assertEquals(1_760_000_000L, params.getLong("session_id"))
    assertTrue("engagement_time_msec must be positive for Firebase Realtime", params.getLong("engagement_time_msec") >= 100L)
    assertEquals("V2Ray:VLESS", params.getString("protocol"))
    assertEquals(145L, params.getLong("latency_ms"))
    assertEquals(3, params.getInt("session_number"))
  }

  @Test
  fun offlineQueue_persistsOnFailure_andFlushesWithSocksPortWhenVpnConnects() {
    Ga4TelemetryRelay.relayUrlOverride = "https://meh-relay.example.workers.dev"

    var allowSuccess = false
    val capturedPosts = mutableListOf<Pair<String, Int>>()
    Ga4TelemetryRelay.transportOverride = Ga4TelemetryRelay.RelayTransport { _, body, socksPort ->
      capturedPosts.add(body to socksPort)
      allowSuccess
    }

    // Before VPN connects: network blocked -> events remain queued persistently
    Ga4TelemetryRelay.socksPortProvider = { 0 }
    Ga4TelemetryRelay.enqueue(context, "app_open", mapOf("session_number" to 1))
    Ga4TelemetryRelay.enqueue(context, "vpn_connect_attempt", mapOf("connection_method" to "V2RAY"))
    assertEquals(2, Ga4TelemetryRelay.queuedCount(context))

    val deliveredBeforeVpn =
      Ga4TelemetryRelay.flushNow(
        context = context,
        appInstanceId = "aabbccddeeff00112233445566778899",
        sessionId = 1000L,
        appVersion = "1.3.20",
      )
    assertEquals(0, deliveredBeforeVpn)
    assertEquals("Failed batch must remain in persistent queue", 2, Ga4TelemetryRelay.queuedCount(context))
    assertEquals(0, capturedPosts.last().second)

    // After VPN connects: local SOCKS5 port 20808 is active -> batch flushes cleanly!
    allowSuccess = true
    Ga4TelemetryRelay.socksPortProvider = { 20808 }
    val deliveredAfterVpn =
      Ga4TelemetryRelay.flushNow(
        context = context,
        appInstanceId = "aabbccddeeff00112233445566778899",
        sessionId = 1000L,
        appVersion = "1.3.20",
      )
    assertEquals(2, deliveredAfterVpn)
    assertEquals("Delivered events must be removed from queue", 0, Ga4TelemetryRelay.queuedCount(context))
    assertEquals(20808, capturedPosts.last().second)

    val sentJson = JSONObject(capturedPosts.last().first)
    assertEquals(2, sentJson.getJSONArray("events").length())
    assertEquals("app_open", sentJson.getJSONArray("events").getJSONObject(0).getString("name"))
    assertEquals("vpn_connect_attempt", sentJson.getJSONArray("events").getJSONObject(1).getString("name"))
  }

  @Test
  fun unconfiguredRelayUrl_doesNotAttemptNetworkDelivery() {
    Ga4TelemetryRelay.relayUrlOverride = ""
    var called = false
    Ga4TelemetryRelay.transportOverride = Ga4TelemetryRelay.RelayTransport { _, _, _ ->
      called = true
      true
    }

    assertFalse(Ga4TelemetryRelay.isConfigured())
    Ga4TelemetryRelay.enqueueAndFlushAsync(
      context = context,
      appInstanceId = "aabbccddeeff00112233445566778899",
      sessionId = 1000L,
      appVersion = "1.3.20",
      eventName = "app_open",
      params = emptyMap(),
    )
    val flushed =
      Ga4TelemetryRelay.flushNow(
        context = context,
        appInstanceId = "aabbccddeeff00112233445566778899",
        sessionId = 1000L,
        appVersion = "1.3.20",
      )
    assertEquals(0, flushed)
    assertFalse("Must never perform network calls when ANALYTICS_RELAY_URL is empty", called)
  }
}
