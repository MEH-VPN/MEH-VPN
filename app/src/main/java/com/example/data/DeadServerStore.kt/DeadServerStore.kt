package com.example.data

import android.content.Context
import org.json.JSONObject

/**
 * Persistent list of V2Ray endpoints (by V2RayConfig.endpointKey) that proved
 * dead after connecting: a node abandoned by the keep-alive failover or by the
 * post-connect verification is remembered for 24 hours, so the next connect
 * does not try it first again. Entries expire lazily on read; a manual server
 * switch never marks a node dead. Stored in the same SharedPreferences file
 * as the saved last-connected candidates ("meh_last_server_prefs") under
 * [KEY_DEAD_SERVERS_JSON], as endpointKey to epoch-ms.
 */
object DeadServerStore {
  private const val PREFS_NAME = "meh_last_server_prefs"
  private const val KEY_DEAD_SERVERS_JSON = "dead_servers_json"

  /** How long a dead mark lasts. After this the node may be tried again. */
  const val DEAD_TTL_MS = 24L * 60L * 60L * 1000L

  /** Marks [endpointKey] dead right now. */
  fun markDead(context: Context, endpointKey: String) {
    if (endpointKey.isBlank()) return
    val entries = loadEntries(context).toMutableMap()
    entries[endpointKey] = System.currentTimeMillis()
    saveEntries(context, entries)
  }

  /**
   * True when [endpointKey] was marked dead within the last 24h. Expired marks
   * are pruned lazily on read.
   */
  fun isDead(context: Context, endpointKey: String): Boolean {
    if (endpointKey.isBlank()) return false
    return deadKeys(context).contains(endpointKey)
  }

  /** Endpoint keys marked dead within the last 24h (expired entries pruned on read). */
  fun deadKeys(context: Context): Set<String> {
    val nowMs = System.currentTimeMillis()
    val entries = loadEntries(context)
    val live = entries.filterValues { markedAtMs -> nowMs - markedAtMs < DEAD_TTL_MS }
    if (live.size != entries.size) saveEntries(context, live)
    return live.keys
  }

  private fun loadEntries(context: Context): Map<String, Long> {
    val raw =
      context
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getString(KEY_DEAD_SERVERS_JSON, null)
        ?: return emptyMap()
    return try {
      val json = JSONObject(raw)
      val out = mutableMapOf<String, Long>()
      val keys = json.keys()
      while (keys.hasNext()) {
        val key = keys.next()
        out[key] = json.optLong(key, 0L)
      }
      out
    } catch (_: Exception) {
      emptyMap()
    }
  }

  private fun saveEntries(context: Context, entries: Map<String, Long>) {
    val json = JSONObject()
    for ((key, markedAtMs) in entries) {
      json.put(key, markedAtMs)
    }
    context
      .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(KEY_DEAD_SERVERS_JSON, json.toString())
      .apply()
  }
}
