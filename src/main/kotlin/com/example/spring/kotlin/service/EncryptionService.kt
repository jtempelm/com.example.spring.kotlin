package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.EncryptedPayload

interface EncryptionService {

    fun generateBase64EncodedKey(length: Int): String

    fun encryptAES(payload: String, encodedKey: String): EncryptedPayload

    fun decryptAES(encryptedPayload: EncryptedPayload): String

    fun encrypt3DES(payload: String, encodedKey: String): EncryptedPayload

    fun decrypt3DES(encryptedPayload: EncryptedPayload): String
}
