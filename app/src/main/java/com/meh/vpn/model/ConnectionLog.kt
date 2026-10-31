package com.meh.vpn.model

import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId
import com.google.firebase.firestore.IgnoreExtraProperties
import com.google.firebase.firestore.ServerTimestamp

@IgnoreExtraProperties
data class ConnectionLog(
    @DocumentId val id: String = "",
    val userId: String = "",
    val countryNameFa: String = "",
    val flagEmoji: String = "",
    val rawUri: String = "",
    val sourceRepo: String = "",
    val pingMs: Long = 0L,
    @ServerTimestamp val createdAt: Timestamp? = null,
    @ServerTimestamp val updatedAt: Timestamp? = null
)
