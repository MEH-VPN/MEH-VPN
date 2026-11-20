/**
 * MEH VPN -> Firebase Analytics / GA4 Measurement Protocol Relay (Cloudflare Worker)
 *
 * Why this exists:
 * 1. Firebase/Google Analytics endpoints are blocked/sanctioned on Iranian IP addresses.
 * 2. Secrets (`GA4_API_SECRET`) MUST stay server-side in Cloudflare Worker Secrets, NEVER inside
 *    the public Android APK distributed on GitHub/Telegram.
 *
 * Required Cloudflare Worker Secrets / Variables (Settings -> Variables and Secrets):
 * - GA4_API_SECRET      (Secret)  : Created in GA4 Admin -> Data Streams -> Measurement Protocol API secrets
 * - FIREBASE_APP_ID     (Var)     : Recommended! Android app stream ID from google-services.json
 *                                   (e.g. "1:468881393461:android:51d7f54ba9686ce0606e7c")
 *                                   Events appear directly in Firebase Console -> Analytics!
 * - GA4_MEASUREMENT_ID  (Var)     : Optional fallback if you use a GA4 Web stream ("G-XXXXXXXXXX")
 *                                   instead of FIREBASE_APP_ID.
 */

const ALLOWED_EVENTS = new Set([
  "app_open",
  "user_active_session",
  "screen_view",
  "vpn_connect_attempt",
  "vpn_configs_fetched",
  "vpn_connected",
  "vpn_active_heartbeat",
  "vpn_disconnected",
  "app_error_report",
  "app_error_flushed",
  "app_crash_recovered",
]);

const MAX_BODY_BYTES = 16 * 1024;
const MAX_EVENTS_PER_BATCH = 25;
const HEX_32_REGEX = /^[0-9a-f]{32}$/;

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function sanitizeParams(rawParams) {
  if (!rawParams || typeof rawParams !== "object" || Array.isArray(rawParams)) {
    return { engagement_time_msec: 100 };
  }
  const clean = {};
  let count = 0;
  for (const [k, v] of Object.entries(rawParams)) {
    if (count >= 25) break;
    const key = String(k).toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 40);
    if (!key || !/^[a-z]/.test(key)) continue;
    if (typeof v === "number" && Number.isFinite(v)) {
      clean[key] = v;
      count++;
    } else if (typeof v === "string") {
      clean[key] = v.slice(0, 100);
      count++;
    } else if (typeof v === "boolean") {
      clean[key] = v ? 1 : 0;
      count++;
    }
  }
  if (typeof clean.engagement_time_msec !== "number" || clean.engagement_time_msec < 1) {
    clean.engagement_time_msec = 100;
  }
  return clean;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check endpoint (never exposes secrets)
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      const hasFirebase = Boolean(env.FIREBASE_APP_ID && env.GA4_API_SECRET);
      const hasGa4Web = Boolean(env.GA4_MEASUREMENT_ID && env.GA4_API_SECRET);
      return jsonResponse({
        ok: hasFirebase || hasGa4Web,
        mode: hasFirebase ? "firebase_app" : hasGa4Web ? "ga4_web" : "unconfigured",
      });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed" }, 405);
    }

    const apiSecret = (env.GA4_API_SECRET || "").trim();
    const firebaseAppId = (env.FIREBASE_APP_ID || "").trim();
    const measurementId = (env.GA4_MEASUREMENT_ID || "").trim();

    if (!apiSecret || (!firebaseAppId && !measurementId)) {
      return jsonResponse({ error: "worker_not_configured" }, 503);
    }

    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > MAX_BODY_BYTES) {
      return jsonResponse({ error: "payload_too_large" }, 413);
    }

    let rawText;
    try {
      rawText = await request.text();
    } catch {
      return jsonResponse({ error: "invalid_body" }, 400);
    }
    if (!rawText || rawText.length > MAX_BODY_BYTES) {
      return jsonResponse({ error: "payload_too_large" }, 413);
    }

    let payload;
    try {
      payload = JSON.parse(rawText);
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const appInstanceId = String(payload.app_instance_id || "").trim().toLowerCase();
    if (!HEX_32_REGEX.test(appInstanceId)) {
      return jsonResponse({ error: "invalid_app_instance_id" }, 400);
    }

    if (!Array.isArray(payload.events) || payload.events.length === 0) {
      return jsonResponse({ error: "missing_events" }, 400);
    }

    const cleanEvents = [];
    for (const ev of payload.events.slice(0, MAX_EVENTS_PER_BATCH)) {
      if (!ev || typeof ev !== "object") continue;
      const name = String(ev.name || "").trim().toLowerCase();
      if (!ALLOWED_EVENTS.has(name)) continue;
      cleanEvents.push({
        name,
        params: sanitizeParams(ev.params),
      });
    }

    if (cleanEvents.length === 0) {
      return jsonResponse({ error: "no_valid_events" }, 400);
    }

    const useFirebaseAppStream = Boolean(firebaseAppId);
    const mpBody = useFirebaseAppStream
      ? {
          app_instance_id: appInstanceId,
          events: cleanEvents,
        }
      : {
          client_id: `${appInstanceId.slice(0, 16)}.${appInstanceId.slice(16)}`,
          events: cleanEvents,
        };

    if (typeof payload.timestamp_micros === "number" && Number.isFinite(payload.timestamp_micros)) {
      mpBody.timestamp_micros = Math.floor(payload.timestamp_micros);
    }

    if (payload.user_properties && typeof payload.user_properties === "object") {
      const cleanProps = {};
      for (const [k, v] of Object.entries(payload.user_properties)) {
        const key = String(k).toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 24);
        if (!key) continue;
        const val = v && typeof v === "object" && "value" in v ? String(v.value).slice(0, 36) : String(v).slice(0, 36);
        cleanProps[key] = { value: val };
      }
      if (Object.keys(cleanProps).length > 0) {
        mpBody.user_properties = cleanProps;
      }
    }

    const endpointBase =
      url.searchParams.get("debug") === "1" && env.ENABLE_DEBUG_ENDPOINT === "true"
        ? "https://www.google-analytics.com/debug/mp/collect"
        : "https://www.google-analytics.com/mp/collect";

    const query = useFirebaseAppStream
      ? `firebase_app_id=${encodeURIComponent(firebaseAppId)}&api_secret=${encodeURIComponent(apiSecret)}`
      : `measurement_id=${encodeURIComponent(measurementId)}&api_secret=${encodeURIComponent(apiSecret)}`;

    const upstream = await fetch(`${endpointBase}?${query}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(mpBody),
    });

    if (endpointBase.includes("/debug/")) {
      const debugJson = await upstream.text();
      return new Response(debugJson, {
        status: upstream.status,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    if (upstream.status >= 200 && upstream.status < 300) {
      return new Response(null, { status: 204 });
    }
    return jsonResponse({ error: "upstream_failed", upstream_status: upstream.status }, 502);
  },
};
