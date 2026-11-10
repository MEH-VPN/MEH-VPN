package com.example

import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfig
import com.example.model.V2RayProtocol
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Round 5: the best-server scan ranks stage-2-verified nodes fastest first,
 * deduplicated by endpoint, and honours the 60-second minimum scan with a
 * 1000 ms early-stop threshold.
 */
class BestServerScanTest {

    private val repository = SoliSpiritRepository()

    private fun config(address: String, latencyMs: Long): V2RayConfig =
        V2RayConfig(
            id = "test-" + address + "-" + latencyMs,
            protocol = V2RayProtocol.VLESS,
            remarks = "test",
            address = address,
            port = 443,
            authId = "00000000-0000-0000-0000-000000000000",
            rawUri = "vless://00000000-0000-0000-0000-000000000000@" + address + ":443",
            latencyMs = latencyMs,
        )

    @Test
    fun scanThresholds() {
        assertEquals(60_000L, SoliSpiritRepository.BEST_SCAN_MIN_DURATION_MS)
        assertEquals(1000L, SoliSpiritRepository.BEST_SCAN_EARLY_STOP_PING_MS)
        assertEquals(5, SoliSpiritRepository.BEST_SCAN_POOL_SIZE)
    }

    @Test
    fun rankVerifiedByPingOrdersFastestFirstAndDeduplicates() {
        val ranked = repository.rankVerifiedByPing(
            listOf(
                config("slow.example.com", 3000L),
                config("fast.example.com", 150L),
                config("mid.example.com", 800L),
                // Same endpoint as the 800 ms node, measured slower: only one copy survives.
                config("mid.example.com", 1200L),
            ),
        )
        assertEquals(listOf(150L, 800L, 3000L), ranked.map { it.latencyMs })
        assertEquals(3, ranked.size)
    }

    @Test
    fun rankVerifiedByPingKeepsTopFive() {
        val ranked = repository.rankVerifiedByPing(
            (1..7).map { i -> config("node" + i + ".example.com", (i * 100).toLong()) },
        )
        assertEquals(5, ranked.size)
        assertEquals(listOf(100L, 200L, 300L, 400L, 500L), ranked.map { it.latencyMs })
    }

    @Test
    fun rankVerifiedByPingKeepsFastestMeasurementOfDuplicateEndpoint() {
        val ranked = repository.rankVerifiedByPing(
            listOf(
                config("same.example.com", 900L),
                config("same.example.com", 250L),
            ),
        )
        assertEquals(1, ranked.size)
        assertEquals(250L, ranked.first().latencyMs)
    }
}
