package com.example.vpn

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Lock-free diagnostic and performance telemetry counters (`MehDiag`) for measuring
 * bottlenecks across DNS resolution, V2Ray node handshakes, pre-warmed connection pooling,
 * mid-stream first-byte stall failovers, UDP relay, TLS verification, and Iranian direct routing.
 */
object MehDiag {

  data class DiagSnapshot(
    val dnsQueriesTotal: Long,
    val dnsSyntheticHits: Long,
    val dnsCacheHits: Long,
    val dnsIranDirectHits: Long,
    val dnsTunnelTcpSuccess: Long,
    val dnsTunnelDohSuccess: Long,
    val dnsDirectDohSuccess: Long,
    val dnsServfailCount: Long,
    val dnsAvgLatencyMs: Long,
    val tcpConnectAttempts: Long,
    val tcpConnectSuccess: Long,
    val tcpConnectFailures: Long,
    val prewarmedPoolHits: Long,
    val prewarmedPoolMisses: Long,
    val prewarmedPoolCreated: Long,
    val clientHelloSent: Long,
    val firstByteReceived: Long,
    val firstByteTimeoutFailovers: Long,
    val keepAliveProbesRun: Long,
    val keepAliveProbesSkippedActiveTraffic: Long,
    val keepAliveTriggeredFailovers: Long,
    val nodeSwitchCount: Long,
    val activeStreams: Int,
    val rejectedStreams: Long,
    val iranDirectBypassCount: Long,
    val udpDnsPackets: Long,
    val udpVlessRelayedPackets: Long,
    val udpIranDirectPackets: Long,
    val udpDroppedPackets: Long,
    val tlsStrictVerifiedCount: Long,
    val tlsPermissiveFallbackCount: Long,
    val totalBytesUploaded: Long,
    val totalBytesDownloaded: Long,
    val lastTrafficTimestampMs: Long,
  val totalRealBytesDownloaded: Long = 0,
  val lastRealDownloadTimestampMs: Long = 0,
  )

  private val _dnsQueriesTotal = AtomicLong(0L)
  private val _dnsSyntheticHits = AtomicLong(0L)
  private val _dnsCacheHits = AtomicLong(0L)
  private val _dnsIranDirectHits = AtomicLong(0L)
  private val _dnsTunnelTcpSuccess = AtomicLong(0L)
  private val _dnsTunnelDohSuccess = AtomicLong(0L)
  private val _dnsDirectDohSuccess = AtomicLong(0L)
  private val _dnsServfailCount = AtomicLong(0L)
  private val _dnsTotalTimeMs = AtomicLong(0L)

  private val _tcpConnectAttempts = AtomicLong(0L)
  private val _tcpConnectSuccess = AtomicLong(0L)
  private val _tcpConnectFailures = AtomicLong(0L)

  private val _prewarmedPoolHits = AtomicLong(0L)
  private val _prewarmedPoolMisses = AtomicLong(0L)
  private val _prewarmedPoolCreated = AtomicLong(0L)

  private val _clientHelloSent = AtomicLong(0L)
  private val _firstByteReceived = AtomicLong(0L)
  private val _firstByteTimeoutFailovers = AtomicLong(0L)

  private val _keepAliveProbesRun = AtomicLong(0L)
  private val _keepAliveProbesSkippedActiveTraffic = AtomicLong(0L)
  private val _keepAliveTriggeredFailovers = AtomicLong(0L)
  private val _nodeSwitchCount = AtomicLong(0L)

  private val _activeStreams = AtomicInteger(0)
  private val _rejectedStreams = AtomicLong(0L)
  private val _iranDirectBypassCount = AtomicLong(0L)

  private val _udpDnsPackets = AtomicLong(0L)
  private val _udpVlessRelayedPackets = AtomicLong(0L)
  private val _udpIranDirectPackets = AtomicLong(0L)
  private val _udpDroppedPackets = AtomicLong(0L)

  private val _tlsStrictVerifiedCount = AtomicLong(0L)
  private val _tlsPermissiveFallbackCount = AtomicLong(0L)

  private val _totalBytesUploaded = AtomicLong(0L)
  private val _totalBytesDownloaded = AtomicLong(0L)
  private val _lastTrafficTimestampMs = AtomicLong(0L)
  private val _lastRealDownloadTimestampMs = AtomicLong(0L)
  private val _totalRealBytesDownloaded = AtomicLong(0L)

  fun recordDnsQueryStart() {
    _dnsQueriesTotal.incrementAndGet()
  }

  fun recordDnsSyntheticHit(elapsedMs: Long = 0L) {
    _dnsSyntheticHits.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsCacheHit(elapsedMs: Long = 0L) {
    _dnsCacheHits.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsIranDirectHit(elapsedMs: Long = 0L) {
    _dnsIranDirectHits.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsTunnelTcpSuccess(elapsedMs: Long) {
    _dnsTunnelTcpSuccess.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsTunnelDohSuccess(elapsedMs: Long) {
    _dnsTunnelDohSuccess.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsDirectDohSuccess(elapsedMs: Long) {
    _dnsDirectDohSuccess.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordDnsServfail(elapsedMs: Long = 0L) {
    _dnsServfailCount.incrementAndGet()
    if (elapsedMs > 0) _dnsTotalTimeMs.addAndGet(elapsedMs)
  }

  fun recordTcpConnectAttempt() {
    _tcpConnectAttempts.incrementAndGet()
  }

  fun recordTcpConnectSuccess() {
    _tcpConnectSuccess.incrementAndGet()
  }

  fun recordTcpConnectFailure() {
    _tcpConnectFailures.incrementAndGet()
  }

  fun recordPrewarmedPoolHit() {
    _prewarmedPoolHits.incrementAndGet()
  }

  fun recordPrewarmedPoolMiss() {
    _prewarmedPoolMisses.incrementAndGet()
  }

  fun recordPrewarmedPoolCreated() {
    _prewarmedPoolCreated.incrementAndGet()
  }

  fun recordClientHelloSent() {
    _clientHelloSent.incrementAndGet()
  }

  fun recordFirstByteReceived() {
    _firstByteReceived.incrementAndGet()
    _lastTrafficTimestampMs.set(System.currentTimeMillis())
  }

  fun recordFirstByteTimeoutFailover() {
    _firstByteTimeoutFailovers.incrementAndGet()
  }

  fun recordKeepAliveProbeRun() {
    _keepAliveProbesRun.incrementAndGet()
  }

  fun recordKeepAliveSkippedActiveTraffic() {
    _keepAliveProbesSkippedActiveTraffic.incrementAndGet()
  }

  fun recordKeepAliveTriggeredFailover() {
    _keepAliveTriggeredFailovers.incrementAndGet()
  }

  fun recordNodeSwitch() {
    _nodeSwitchCount.incrementAndGet()
  }

  fun onStreamOpened() {
    _activeStreams.incrementAndGet()
  }

  fun onStreamClosed() {
    _activeStreams.updateAndGet { current -> if (current > 0) current - 1 else 0 }
  }

  fun recordStreamRejected() {
    _rejectedStreams.incrementAndGet()
  }

  fun recordIranDirectBypass() {
    _iranDirectBypassCount.incrementAndGet()
  }

  fun recordUdpDnsPacket() {
    _udpDnsPackets.incrementAndGet()
  }

  fun recordUdpVlessRelayedPacket() {
    _udpVlessRelayedPackets.incrementAndGet()
    _lastTrafficTimestampMs.set(System.currentTimeMillis())
  }

  fun recordUdpIranDirectPacket() {
    _udpIranDirectPackets.incrementAndGet()
  }

  fun recordUdpDroppedPacket() {
    _udpDroppedPackets.incrementAndGet()
  }

  fun recordTlsStrictVerified() {
    _tlsStrictVerifiedCount.incrementAndGet()
  }

  fun recordTlsPermissiveFallback() {
    _tlsPermissiveFallbackCount.incrementAndGet()
  }

  fun recordBytesUploaded(bytes: Long) {
    if (bytes > 0L) {
      _totalBytesUploaded.addAndGet(bytes)
    }
  }

  /**
   * Real downstream payload through a TCP relay: first response bytes and relayed
   * download bytes. DNS and UDP replies must NOT call this; they count only via
   * [recordBytesDownloaded], so a trickle of DNS answers can never look like a
   * working connection for the keep-alive watchdog.
   */
  fun recordRealDownloadBytes(bytes: Long) {
    val safeAmount = bytes.coerceAtLeast(0L)
    _totalBytesDownloaded.addAndGet(safeAmount)
    if (safeAmount > 0L) {
      _totalRealBytesDownloaded.addAndGet(safeAmount)
      val nowMs = System.currentTimeMillis()
      _lastRealDownloadTimestampMs.set(nowMs)
      _lastTrafficTimestampMs.set(nowMs)
    }
  }

  /** True when real (non-DNS) download bytes arrived within [withinMs]. */
  fun hasRecentRealDownloadTraffic(withinMs: Long): Boolean {
    val lastRealMs = _lastRealDownloadTimestampMs.get()
    if (lastRealMs <= 0L) return false
    return (System.currentTimeMillis() - lastRealMs) <= withinMs
  }

  fun recordBytesDownloaded(bytes: Long) {
    if (bytes > 0L) {
      _totalBytesDownloaded.addAndGet(bytes)
      _lastTrafficTimestampMs.set(System.currentTimeMillis())
    }
  }

  fun hasRecentDownloadTraffic(withinMs: Long): Boolean {
    val lastTs = _lastTrafficTimestampMs.get()
    if (lastTs <= 0L) return false
    return (System.currentTimeMillis() - lastTs) in 0..withinMs
  }

  fun snapshot(): DiagSnapshot {
    val totalDns = _dnsQueriesTotal.get()
    val avgDnsMs = if (totalDns > 0L) _dnsTotalTimeMs.get() / totalDns else 0L
    return DiagSnapshot(
      dnsQueriesTotal = totalDns,
      dnsSyntheticHits = _dnsSyntheticHits.get(),
      dnsCacheHits = _dnsCacheHits.get(),
      dnsIranDirectHits = _dnsIranDirectHits.get(),
      dnsTunnelTcpSuccess = _dnsTunnelTcpSuccess.get(),
      dnsTunnelDohSuccess = _dnsTunnelDohSuccess.get(),
      dnsDirectDohSuccess = _dnsDirectDohSuccess.get(),
      dnsServfailCount = _dnsServfailCount.get(),
      dnsAvgLatencyMs = avgDnsMs,
      tcpConnectAttempts = _tcpConnectAttempts.get(),
      tcpConnectSuccess = _tcpConnectSuccess.get(),
      tcpConnectFailures = _tcpConnectFailures.get(),
      prewarmedPoolHits = _prewarmedPoolHits.get(),
      prewarmedPoolMisses = _prewarmedPoolMisses.get(),
      prewarmedPoolCreated = _prewarmedPoolCreated.get(),
      clientHelloSent = _clientHelloSent.get(),
      firstByteReceived = _firstByteReceived.get(),
      firstByteTimeoutFailovers = _firstByteTimeoutFailovers.get(),
      keepAliveProbesRun = _keepAliveProbesRun.get(),
      keepAliveProbesSkippedActiveTraffic = _keepAliveProbesSkippedActiveTraffic.get(),
      keepAliveTriggeredFailovers = _keepAliveTriggeredFailovers.get(),
      nodeSwitchCount = _nodeSwitchCount.get(),
      activeStreams = _activeStreams.get(),
      rejectedStreams = _rejectedStreams.get(),
      iranDirectBypassCount = _iranDirectBypassCount.get(),
      udpDnsPackets = _udpDnsPackets.get(),
      udpVlessRelayedPackets = _udpVlessRelayedPackets.get(),
      udpIranDirectPackets = _udpIranDirectPackets.get(),
      udpDroppedPackets = _udpDroppedPackets.get(),
      tlsStrictVerifiedCount = _tlsStrictVerifiedCount.get(),
      tlsPermissiveFallbackCount = _tlsPermissiveFallbackCount.get(),
      totalBytesUploaded = _totalBytesUploaded.get(),
      totalBytesDownloaded = _totalBytesDownloaded.get(),
      totalRealBytesDownloaded = _totalRealBytesDownloaded.get(),
      lastRealDownloadTimestampMs = _lastRealDownloadTimestampMs.get(),
      lastTrafficTimestampMs = _lastTrafficTimestampMs.get(),
    )
  }

  fun formatCompactSummary(): String {
    val s = snapshot()
    return "DNS[total=${s.dnsQueriesTotal},synth=${s.dnsSyntheticHits},cache=${s.dnsCacheHits},ir=${s.dnsIranDirectHits}] " +
      "TCP[ok=${s.tcpConnectSuccess}/${s.tcpConnectAttempts},poolHit=${s.prewarmedPoolHits},irDirect=${s.iranDirectBypassCount}] " +
      "FAILOVER[1stByte=${s.firstByteTimeoutFailovers},ka=${s.keepAliveTriggeredFailovers},switches=${s.nodeSwitchCount}] " +
      "TLS[strict=${s.tlsStrictVerifiedCount},fallback=${s.tlsPermissiveFallbackCount}] " +
      "UDP[dns=${s.udpDnsPackets},vless=${s.udpVlessRelayedPackets},ir=${s.udpIranDirectPackets}]"
  }

  fun reset() {
    _dnsQueriesTotal.set(0L)
    _dnsSyntheticHits.set(0L)
    _dnsCacheHits.set(0L)
    _dnsIranDirectHits.set(0L)
    _dnsTunnelTcpSuccess.set(0L)
    _dnsTunnelDohSuccess.set(0L)
    _dnsDirectDohSuccess.set(0L)
    _dnsServfailCount.set(0L)
    _dnsTotalTimeMs.set(0L)
    _tcpConnectAttempts.set(0L)
    _tcpConnectSuccess.set(0L)
    _tcpConnectFailures.set(0L)
    _prewarmedPoolHits.set(0L)
    _prewarmedPoolMisses.set(0L)
    _prewarmedPoolCreated.set(0L)
    _clientHelloSent.set(0L)
    _firstByteReceived.set(0L)
    _firstByteTimeoutFailovers.set(0L)
    _keepAliveProbesRun.set(0L)
    _keepAliveProbesSkippedActiveTraffic.set(0L)
    _keepAliveTriggeredFailovers.set(0L)
    _nodeSwitchCount.set(0L)
    _activeStreams.set(0)
    _rejectedStreams.set(0L)
    _iranDirectBypassCount.set(0L)
    _udpDnsPackets.set(0L)
    _udpVlessRelayedPackets.set(0L)
    _udpIranDirectPackets.set(0L)
    _udpDroppedPackets.set(0L)
    _tlsStrictVerifiedCount.set(0L)
    _tlsPermissiveFallbackCount.set(0L)
    _totalBytesUploaded.set(0L)
    _totalBytesDownloaded.set(0L)
    _totalRealBytesDownloaded.set(0L)
    _lastRealDownloadTimestampMs.set(0L)
    _lastTrafficTimestampMs.set(0L)
  }
}
