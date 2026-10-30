package com.example.data

import android.content.Context
import com.example.R
import com.example.model.ConnectionLog
import com.google.firebase.Firebase
import com.google.firebase.Timestamp
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.auth
import com.google.firebase.firestore.DocumentSnapshot
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.snapshots
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.tasks.await

class MehFirebaseRepository(
    private val db: FirebaseFirestore,
    private val auth: FirebaseAuth = Firebase.auth
) {
    constructor(context: Context) : this(
        db = FirebaseFirestore.getInstance(
            context.applicationContext.getString(R.string.firestore_database_id)
        ),
        auth = Firebase.auth
    )

    private fun requireUserId(): String =
        auth.currentUser?.uid
            ?: throw IllegalStateException("User must be authenticated before performing Firestore operations")

    suspend fun saveConnectionLog(
        countryNameFa: String,
        flagEmoji: String,
        rawUri: String,
        sourceRepo: String,
        pingMs: Long
    ): Result<String> {
        val uid = try {
            requireUserId()
        } catch (e: Exception) {
            return Result.failure(e)
        }
        val collectionRef = db.collection("users").document(uid).collection("connection_logs")
        val docRef = collectionRef.document()
        val log = ConnectionLog(
            userId = uid,
            countryNameFa = countryNameFa.take(60).ifBlank { "آلمان" },
            flagEmoji = flagEmoji.take(20).ifBlank { "🇩🇪" },
            rawUri = rawUri.take(2048),
            sourceRepo = sourceRepo.take(200).ifBlank { "GitHub" },
            pingMs = pingMs.coerceIn(0L, 60000L),
            createdAt = null,
            updatedAt = null
        )
        return try {
            docRef.set(log).await()
            Result.success(docRef.id)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            handleFirestoreError(e, OperationType.CREATE, docRef.path)
            Result.failure(e)
        }
    }

    suspend fun getUserConnectionLogs(): Result<List<ConnectionLog>> {
        val uid = try {
            requireUserId()
        } catch (e: Exception) {
            return Result.failure(e)
        }
        val collectionPath = "users/$uid/connection_logs"
        return try {
            val snapshot = db.collection("users")
                .document(uid)
                .collection("connection_logs")
                .get()
                .await()
            val logs = snapshot
                .toObjects(ConnectionLog::class.java, DocumentSnapshot.ServerTimestampBehavior.ESTIMATE)
                .sortedByDescending { it.createdAt ?: Timestamp(0, 0) }
            Result.success(logs)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            handleFirestoreError(e, OperationType.LIST, collectionPath)
            Result.failure(e)
        }
    }

    suspend fun getConnectionLogById(targetUserId: String, logId: String): Result<ConnectionLog?> {
        val docRef = db.collection("users")
            .document(targetUserId)
            .collection("connection_logs")
            .document(logId)
        return try {
            val snapshot = docRef.get().await()
            val item = snapshot.toObject(
                ConnectionLog::class.java,
                DocumentSnapshot.ServerTimestampBehavior.ESTIMATE
            )
            Result.success(item)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            handleFirestoreError(e, OperationType.GET, docRef.path)
            Result.failure(e)
        }
    }

    fun observeConnectionLogs(userId: String = auth.currentUser?.uid.orEmpty()): Flow<List<ConnectionLog>> {
        val targetUid = userId.ifBlank { "unauthenticated_uid" }
        return db.collection("users")
            .document(targetUid)
            .collection("connection_logs")
            .snapshots()
            .map { snapshot ->
                snapshot
                    .toObjects(ConnectionLog::class.java, DocumentSnapshot.ServerTimestampBehavior.ESTIMATE)
                    .sortedByDescending { it.createdAt ?: Timestamp(0, 0) }
            }
    }
}
