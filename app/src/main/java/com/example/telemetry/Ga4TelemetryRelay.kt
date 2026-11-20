package com.example.telemetry

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import com.example.BuildConfig
import com.example.vpn.MehVpnService
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * Lightweight, sanction-resilient Firebase Analytics / GA4 Measurement Protocol relay client.
 *
 * Why this replaces the Firebase Android SDK inside a VPN app:
 * 1. Direct Firebase SDK calls are blocked/sanctioned on Iranian ISPs AND bypass our VPN tunnel
 *    because `MehVpnService` calls `addDisallowedApplication(packageName)` to avoid routing loops.
 * 2. Zero third-party SDK bloat (uses standard `HttpURLConnection` + `SSLSocket` + `org.json`).
 * 3. Zero secrets inside the public APK: `GA4_API_SECRET` lives exclusively on the user's
 *    Cloudflare Worker; the APK only knows the public relay URL (`BuildConfig.ANALYTICS_RELAY_URL`).
 * 4. Dual transport:
 *    - Primary: Direct HTTPS POST to the Cloudflare Worker (works even BEFORE VPN connects).
 *    - Fallback: Local VPN SOCKS5 proxy (`127.0.0.1:localProxyPort`) with remote domain resolution
 *      (`ATYP = 0x03`) so events succeed even if an ISP throttles/blocks `*.workers.dev`.
 * 5. Persistent offline queue (`SharedPreferences`) automatically flushed on app open, VPN
 *    connection, and periodic active heartbeats.
 */
object Ga4TelemetryRelay {

  private const val TAG = "Ga4TelemetryRelay"
  private const val PREFS_NAME = "meh_ga4_relay_queue"
  private const val KEY_QUEUED_EVENTS = "queued_events_v1"
  private const val MAX_QUEUED_EVENTS = 40
  private const val MAX_BATCH_SIZE = 20
  private const val MAX_BACKFILL_AGE_MS = 70L * 60L * 60L * 1000L // GA4 allows up to 72h backfill
  private const val CONNECT_TIMEOUT_MS = 6_000
  private const val READ_TIMEOUT_MS = 6_000
  private val HEX_32_REGEX = Regex("^[0-9a-f]{32}$")
  private val EVENT_NAME_REGEX = Regex("^[a-z][a-z0-9_]{0,39}$")

  internal data class QueuedEvent(
    val name: String,
    val params: Map<String, Any>,
    val timestampMs: Long,
  )

  internal fun interface RelayTransport {
    /**
     * Posts [jsonBody] to [relayUrl]. When [socksProxyPort] > 0, attempts direct delivery first
     * and falls back to routing through the local VPN SOCKS5 tunnel if direct delivery fails.
     * Returns true on HTTP 2xx.
     */
    fun postJson(relayUrl: String, jsonBody: String, socksProxyPort: Int): Boolean
  }

  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private val isFlushing = AtomicBoolean(false)
  private val queueLock = Any()

  @Volatile internal var relayUrlOverride: String? = null
  @Volatile internal var transportOverride: RelayTransport? = null
  @Volatile internal var socksPortProvider: () -> Int = {
    val session = MehVpnService.tunnelSession.value
    if (session.isRunning && session.localProxyPort in 1..65535) session.localProxyPort else 0
  }

  fun resolvedRelayUrl(): String {
    val raw = (relayUrlOverride ?: BuildConfig.ANALYTICS_RELAY_URL).trim()
    return if (raw.startsWith("https://") || raw.startsWith("http://")) raw else ""
  }

  fun isConfigured(): Boolean = resolvedRelayUrl().isNotEmpty()

  /**
   * Ensures a GA4/Firebase Measurement Protocol compliant 32-char lowercase hex `app_instance_id`.
   */
  fun normalizeAppInstanceId(raw: String?): String {
    val cleaned = raw?.trim()?.lowercase()?.replace("-", "").orEmpty()
    if (HEX_32_REGEX.matches(cleaned)) return cleaned
    return UUID.randomUUID().toString().replace("-", "").lowercase()
  }

  fun enqueueAndFlushAsync(
    context: Context,
    appInstanceId: String,
    sessionId: Long,
    appVersion: String,
    eventName: String,
    params: Map<String, Any>,
  ) {
    if (!isConfigured()) return
    enqueue(context, eventName, params)
    flushAsync(context, appInstanceId, sessionId, appVersion)
  }

  internal fun enqueue(
    context: Context,
    eventName: String,
    params: Map<String, Any>,
    nowMs: Long = System.currentTimeMillis(),
  ) {
    val cleanName = sanitizeEventName(eventName) ?: return
    val cleanParams = sanitizeParams(params)
    synchronized(queueLock) {
      val list = loadQueueLocked(context).toMutableList()
      list.add(QueuedEvent(name = cleanName, params = cleanParams, timestampMs = nowMs))
      val trimmed = if (list.size > MAX_QUEUED_EVENTS) list.takeLast(MAX_QUEUED_EVENTS) else list
      saveQueueLocked(context, trimmed)
    }
  }

  fun queuedCount(context: Context): Int {
    synchronized(queueLock) {
      return loadQueueLocked(context).size
    }
  }

  fun flushAsync(
    context: Context,
    appInstanceId: String,
    sessionId: Long,
    appVersion: String,
  ) {
    if (!isConfigured()) return
    val appCtx = context.applicationContext ?: context
    scope.launch {
      flushNow(
        context = appCtx,
        appInstanceId = appInstanceId,
        sessionId = sessionId,
        appVersion = appVersion,
      )
    }
  }

  /**
   * Synchronously flushes queued events in batches. Safe to call from background threads or tests.
   * Returns total number of events delivered to the relay.
   */
  internal fun flushNow(
    context: Context,
    appInstanceId: String,
    sessionId: Long,
    appVersion: String,
    nowMs: Long = System.currentTimeMillis(),
  ): Int {
    val url = resolvedRelayUrl()
    if (url.isEmpty()) return 0
    if (!isFlushing.compareAndSet(false, true)) return 0

    var deliveredTotal = 0
    try {
      while (true) {
        val batch: List<QueuedEvent> =
          synchronized(queueLock) {
            val fresh =
              loadQueueLocked(context).filter { ev ->
                nowMs - ev.timestampMs <= MAX_BACKFILL_AGE_MS
              }
            if (fresh.isEmpty()) {
              saveQueueLocked(context, emptyList())
              emptyList()
            } else {
              fresh.take(MAX_BATCH_SIZE)
            }
          }
        if (batch.isEmpty()) break

        val payloadJson =
          buildMeasurementPayload(
            appInstanceId = normalizeAppInstanceId(appInstanceId),
            sessionId = sessionId,
            appVersion = appVersion,
            events = batch,
            nowMs = nowMs,
          )
        val socksPort = runCatching { socksPortProvider() }.getOrDefault(0)
        val transport = transportOverride ?: defaultTransport
        val ok = runCatching { transport.postJson(url, payloadJson, socksPort) }.getOrDefault(false)
        if (!ok) {
          break
        }

        deliveredTotal += batch.size
        synchronized(queueLock) {
          val remaining = loadQueueLocked(context).drop(batch.size)
          saveQueueLocked(context, remaining)
        }
      }
    } finally {
      isFlushing.set(false)
    }
    return deliveredTotal
  }

  /**
   * Builds a Firebase Analytics / GA4 Measurement Protocol JSON payload.
   * Includes `session_id` and `engagement_time_msec` on every event so Firebase Realtime and
   * Active Users (DAU/MAU) attribute every active device properly.
   */
  internal fun buildMeasurementPayload(
    appInstanceId: String,
    sessionId: Long,
    appVersion: String,
    events: List<QueuedEvent>,
    nowMs: Long = System.currentTimeMillis(),
  ): String {
    val normalizedId = normalizeAppInstanceId(appInstanceId)
    val root = JSONObject()
    root.put("app_instance_id", normalizedId)

    // Backfill timestamp when flushing a batch recorded earlier while offline/blocked.
    val newestEventMs = events.maxOfOrNull { it.timestampMs } ?: nowMs
    val ageMs = (nowMs - newestEventMs).coerceAtLeast(0L)
    if (ageMs in 5_000L..MAX_BACKFILL_AGE_MS) {
      root.put("timestamp_micros", newestEventMs * 1_000L)
    }

    val userProps =
      JSONObject().apply {
        put("app_ver", JSONObject().put("value", appVersion.take(36)))
        put("android_sdk", JSONObject().put("value", Build.VERSION.SDK_INT.toString()))
      }
    root.put("user_properties", userProps)

    val eventsArr = JSONArray()
    for (ev in events.take(MAX_BATCH_SIZE)) {
      val paramsObj = JSONObject()
      paramsObj.put("session_id", sessionId)
      paramsObj.put("engagement_time_msec", 100L)
      paramsObj.put("app_version", appVersion.take(36))
      for ((k, v) in ev.params) {
        when (v) {
          is Int -> paramsObj.put(k, v)
          is Long -> paramsObj.put(k, v)
          is Double -> paramsObj.put(k, v)
          is Boolean -> paramsObj.put(k, if (v) 1 else 0)
          else -> paramsObj.put(k, v.toString().take(100))
        }
      }
      eventsArr.put(
        JSONObject().apply {
          put("name", ev.name)
          put("params", paramsObj)
        }
      )
    }
    root.put("events", eventsArr)
    return root.toString()
  }

  private val defaultTransport = RelayTransport { relayUrl, jsonBody, socksProxyPort ->
    if (postDirect(relayUrl, jsonBody)) {
      true
    } else if (socksProxyPort in 1..65535) {
      postViaLocalSocks5(relayUrl, jsonBody, socksProxyPort)
    } else {
      false
    }
  }

  private fun postDirect(relayUrl: String, jsonBody: String): Boolean {
    var conn: HttpURLConnection? = null
    return try {
      conn =
        (URL(relayUrl).openConnection() as HttpURLConnection).apply {
          requestMethod = "POST"
          connectTimeout = CONNECT_TIMEOUT_MS
          readTimeout = READ_TIMEOUT_MS
          doOutput = true
          useCaches = false
          setRequestProperty("Content-Type", "application/json; charset=utf-8")
          setRequestProperty("User-Agent", "MEH-VPN-Android/${BuildConfig.VERSION_NAME}")
        }
      val bytes = jsonBody.toByteArray(StandardCharsets.UTF_8)
      conn.outputStream.use { it.write(bytes) }
      val code = conn.responseCode
      code in 200..299
    } catch (t: Throwable) {
      Log.d(TAG, "Direct telemetry relay post failed: ${t.message}")
      false
    } finally {
      runCatching { conn?.disconnect() }
    }
  }

  /**
   * Sends the HTTPS POST through our active local Xray SOCKS5 proxy using SOCKS5 `ATYP = 0x03`
   * (remote DNS resolution inside the VPN tunnel). This guarantees telemetry delivery even when
   * `addDisallowedApplication(packageName)` is active AND the user's ISP blocks/poisons
   * Cloudflare Worker domains.
   */
  private fun postViaLocalSocks5(
    relayUrl: String,
    jsonBody: String,
    socksPort: Int,
  ): Boolean {
    val parsed = runCatching { URL(relayUrl) }.getOrNull() ?: return false
    val host = parsed.host?.takeIf { it.isNotBlank() } ?: return false
    val isHttps = parsed.protocol.equals("https", ignoreCase = true)
    val port = if (parsed.port > 0) parsed.port else if (isHttps) 443 else 80
    val path =
      buildString {
        append(parsed.path.ifBlank { "/" })
        if (!parsed.query.isNullOrBlank()) {
          append('?')
          append(parsed.query)
        }
      }

    var rawSocket: Socket? = null
    var activeSocket: Socket? = null
    return try {
      rawSocket = Socket()
      rawSocket.connect(InetSocketAddress("127.0.0.1", socksPort), CONNECT_TIMEOUT_MS)
      rawSocket.soTimeout = READ_TIMEOUT_MS

      val rawOut = rawSocket.getOutputStream()
      val rawIn = rawSocket.getInputStream()

      // 1. SOCKS5 greeting (no auth)
      rawOut.write(byteArrayOf(0x05, 0x01, 0x00))
      rawOut.flush()
      val greeting = ByteArray(2)
      if (!readFully(rawIn, greeting) || greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) {
        return false
      }

      // 2. SOCKS5 CONNECT with ATYP=0x03 (domain name resolved remotely by Xray)
      val hostBytes = host.toByteArray(StandardCharsets.US_ASCII)
      if (hostBytes.size > 255) return false
      val req =
        ByteArrayOutputStream(7 + hostBytes.size).apply {
          write(0x05)
          write(0x01) // CONNECT
          write(0x00) // RSV
          write(0x03) // DOMAINNAME
          write(hostBytes.size)
          write(hostBytes)
          write((port shr 8) and 0xFF)
          write(port and 0xFF)
        }.toByteArray()
      rawOut.write(req)
      rawOut.flush()

      val hdr = ByteArray(4)
      if (!readFully(rawIn, hdr) || hdr[0] != 0x05.toByte() || hdr[1] != 0x00.toByte()) {
        return false
      }
      val skipLen =
        when (hdr[3].toInt() and 0xFF) {
          0x01 -> 4 + 2
          0x04 -> 16 + 2
          0x03 -> {
            val lenByte = rawIn.read()
            if (lenByte < 0) return false
            lenByte + 2
          }
          else -> return false
        }
      val discard = ByteArray(skipLen)
      if (!readFully(rawIn, discard)) return false

      // 3. Upgrade to strict TLS if HTTPS
      activeSocket =
        if (isHttps) {
          val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
          val ssl = sslFactory.createSocket(rawSocket, host, port, true) as SSLSocket
          ssl.soTimeout = READ_TIMEOUT_MS
          ssl.startHandshake()
          val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
          if (!verifier.verify(host, ssl.session)) {
            return false
          }
          ssl
        } else {
          rawSocket
        }

      // 4. Send HTTP/1.1 POST
      val bodyBytes = jsonBody.toByteArray(StandardCharsets.UTF_8)
      val httpReq =
        buildString {
          append("POST ").append(path).append(" HTTP/1.1\r\n")
          append("Host: ").append(host).append("\r\n")
          append("Content-Type: application/json; charset=utf-8\r\n")
          append("Content-Length: ").append(bodyBytes.size).append("\r\n")
          append("User-Agent: MEH-VPN-Android/").append(BuildConfig.VERSION_NAME).append("\r\n")
          append("Connection: close\r\n\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)

      val out = activeSocket.getOutputStream()
      out.write(httpReq)
      out.write(bodyBytes)
      out.flush()

      val reader = BufferedInputStream(activeSocket.getInputStream())
      val statusLine = readAsciiLine(reader) ?: return false
      val parts = statusLine.split(' ')
      val code = parts.getOrNull(1)?.toIntOrNull() ?: return false
      code in 200..299
    } catch (t: Throwable) {
      Log.d(TAG, "SOCKS5 telemetry relay post failed: ${t.message}")
      false
    } finally {
      runCatching { activeSocket?.close() }
      runCatching { rawSocket?.close() }
    }
  }

  private fun readFully(input: java.io.InputStream, buffer: ByteArray): Boolean {
    var offset = 0
    while (offset < buffer.size) {
      val n = input.read(buffer, offset, buffer.size - offset)
      if (n <= 0) return false
      offset += n
    }
    return true
  }

  private fun readAsciiLine(input: java.io.InputStream): String? {
    val sb = StringBuilder(64)
    while (sb.length < 512) {
      val b = input.read()
      if (b < 0) break
      if (b == '\n'.code) break
      if (b != '\r'.code) sb.append(b.toChar())
    }
    return if (sb.isEmpty()) null else sb.toString()
  }

  private fun sanitizeEventName(raw: String): String? {
    val cleaned = raw.trim().lowercase().replace(Regex("[^a-z0-9_]"), "_").take(40)
    return cleaned.takeIf { EVENT_NAME_REGEX.matches(it) }
  }

  private fun sanitizeParams(raw: Map<String, Any>): Map<String, Any> {
    val out = LinkedHashMap<String, Any>()
    for ((k, v) in raw) {
      if (out.size >= 20) break
      val key = k.trim().lowercase().replace(Regex("[^a-z0-9_]"), "_").take(40)
      if (key.isEmpty() || !key[0].isLetter()) continue
      when (v) {
        is Int, is Long, is Double, is Boolean -> out[key] = v
        else -> out[key] = v.toString().take(100)
      }
    }
    return out
  }

  private fun getPrefs(context: Context): SharedPreferences? =
    runCatching {
      (context.applicationContext ?: context).getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }.getOrNull()

  private fun loadQueueLocked(context: Context): List<QueuedEvent> {
    val raw = getPrefs(context)?.getString(KEY_QUEUED_EVENTS, null) ?: return emptyList()
    if (raw.isBlank()) return emptyList()
    return try {
      val arr = JSONArray(raw)
      val list = ArrayList<QueuedEvent>(arr.length())
      for (i in 0 until arr.length()) {
        val obj = arr.optJSONObject(i) ?: continue
        val name = sanitizeEventName(obj.optString("name", "")) ?: continue
        val ts = obj.optLong("ts", System.currentTimeMillis())
        val paramsJson = obj.optJSONObject("params")
        val paramsMap = LinkedHashMap<String, Any>()
        if (paramsJson != null) {
          val keys = paramsJson.keys()
          while (keys.hasNext()) {
            val k = keys.next()
            val v = paramsJson.opt(k)
            if (v != null && v != JSONObject.NULL) {
              paramsMap[k] = v
            }
          }
        }
        list.add(QueuedEvent(name = name, params = paramsMap, timestampMs = ts))
      }
      list
    } catch (_: Throwable) {
      emptyList()
    }
  }

  private fun saveQueueLocked(context: Context, events: List<QueuedEvent>) {
    val prefs = getPrefs(context) ?: return
    if (events.isEmpty()) {
      prefs.edit().remove(KEY_QUEUED_EVENTS).apply()
      return
    }
    val arr = JSONArray()
    for (ev in events) {
      val paramsObj = JSONObject()
      for ((k, v) in ev.params) {
        paramsObj.put(k, v)
      }
      arr.put(
        JSONObject().apply {
          put("name", ev.name)
          put("ts", ev.timestampMs)
          put("params", paramsObj)
        }
      )
    }
    prefs.edit().putString(KEY_QUEUED_EVENTS, arr.toString()).apply()
  }

  internal fun clearQueueForTests(context: Context) {
    synchronized(queueLock) {
      getPrefs(context)?.edit()?.remove(KEY_QUEUED_EVENTS)?.apply()
    }
  }
}
