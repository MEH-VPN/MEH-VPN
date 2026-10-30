package com.example.data

import com.example.base.FirestoreEmulatorTestBase
import com.google.firebase.firestore.FirebaseFirestoreException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MehFirebaseRepositoryRuleTest : FirestoreEmulatorTestBase() {

    @Test
    fun saveConnectionLog_validPayload_createsDocumentAndReturnsId() = runBlocking {
        signInTestUser(ALICE_EMAIL)
        val repository = MehFirebaseRepository(firestore, auth)

        val createResult = withTimeout(DEFAULT_TIMEOUT_MS) {
            repository.saveConnectionLog(
                countryNameFa = "آلمان",
                flagEmoji = "🇩🇪",
                rawUri = SAMPLE_URI,
                sourceRepo = "SoliSpirit/v2ray-configs",
                pingMs = 78L
            )
        }
        assertTrue(createResult.isSuccess)
        val logId = createResult.getOrThrow()
        assertTrue(logId.isNotEmpty())
    }

    @Test
    fun getUserConnectionLogs_authenticatedOwner_returnsMatchingLogs() = runBlocking {
        signInTestUser(ALICE_EMAIL)
        val repository = MehFirebaseRepository(firestore, auth)
        val logId = withTimeout(DEFAULT_TIMEOUT_MS) {
            repository.saveConnectionLog(
                countryNameFa = "هلند",
                flagEmoji = "🇳🇱",
                rawUri = SAMPLE_URI,
                sourceRepo = "MohammadBahemmat/V2ray-Collector",
                pingMs = 92L
            ).getOrThrow()
        }

        val logsResult = withTimeout(DEFAULT_TIMEOUT_MS) {
            repository.getUserConnectionLogs()
        }
        assertTrue(logsResult.isSuccess)
        assertTrue(logsResult.getOrThrow().map { it.id }.contains(logId))
    }

    @Test
    fun observeConnectionLogs_authenticatedOwner_emitsRealtimeUpdates() = runBlocking {
        val aliceUid = signInTestUser(ALICE_EMAIL)
        val repository = MehFirebaseRepository(firestore, auth)
        val logId = withTimeout(DEFAULT_TIMEOUT_MS) {
            repository.saveConnectionLog(
                countryNameFa = "فنلاند",
                flagEmoji = "🇫🇮",
                rawUri = SAMPLE_URI,
                sourceRepo = "SoliSpirit/v2ray-configs",
                pingMs = 64L
            ).getOrThrow()
        }

        val emittedLogs = withTimeout(FLOW_TIMEOUT_MS) {
            repository.observeConnectionLogs(aliceUid).first { list -> list.any { it.id == logId } }
        }
        assertTrue(emittedLogs.map { it.id }.contains(logId))
    }

    @Test
    fun getConnectionLogById_crossUserAccess_failsWithPermissionDenied() = runBlocking {
        val aliceUid = signInTestUser(ALICE_EMAIL)
        val aliceRepo = MehFirebaseRepository(firestore, auth)
        val logId = withTimeout(DEFAULT_TIMEOUT_MS) {
            aliceRepo.saveConnectionLog(
                countryNameFa = "آلمان",
                flagEmoji = "🇩🇪",
                rawUri = SAMPLE_URI,
                sourceRepo = "SoliSpirit/v2ray-configs",
                pingMs = 80L
            ).getOrThrow()
        }

        signInTestUser(BOB_EMAIL)
        val bobRepo = MehFirebaseRepository(firestore, auth)
        val result = withTimeout(DEFAULT_TIMEOUT_MS) {
            bobRepo.getConnectionLogById(aliceUid, logId)
        }
        assertTrue(result.isFailure)
        val firestoreException = result.exceptionOrNull()?.unwrapFirestoreException()
        assertNotNull(firestoreException)
        assertEquals(FirebaseFirestoreException.Code.PERMISSION_DENIED, firestoreException?.code)
    }

    @Test
    fun observeConnectionLogs_unauthenticatedUser_failsWithPermissionDenied() = runBlocking {
        val aliceUid = signInTestUser(ALICE_EMAIL)
        auth.signOut()
        val repository = MehFirebaseRepository(firestore, auth)

        var caught: Throwable? = null
        try {
            withTimeout(FLOW_TIMEOUT_MS) {
                repository.observeConnectionLogs(aliceUid).first()
            }
        } catch (e: Throwable) {
            caught = e
        }
        assertNotNull(caught)
        val firestoreException = checkNotNull(caught?.unwrapFirestoreException()) {
            "Expected nested FirebaseFirestoreException, got $caught"
        }
        assertEquals(FirebaseFirestoreException.Code.PERMISSION_DENIED, firestoreException.code)
    }

    private companion object {
        const val ALICE_EMAIL = "alice@test.com"
        const val BOB_EMAIL = "bob@test.com"
        const val SAMPLE_URI = "vless://11111111-2222-3333-4444-555555555555@de.meh.example.com:443?security=tls#DE"
        const val DEFAULT_TIMEOUT_MS = 5000L
        const val FLOW_TIMEOUT_MS = 3000L
    }
}
