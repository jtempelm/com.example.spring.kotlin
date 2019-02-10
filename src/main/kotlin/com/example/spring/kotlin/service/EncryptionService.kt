package com.example.spring.kotlin.service

interface EncryptionService {

    fun generateBase64EncodedAESKey(): String

    fun encryptAES(payload: String, encodedKey: String): String

    fun decryptAES(encryptedPayload: String, encodedKey: String): String
}
