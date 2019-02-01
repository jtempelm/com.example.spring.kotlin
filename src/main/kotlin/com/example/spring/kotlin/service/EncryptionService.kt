package com.example.spring.kotlin.service

interface EncryptionService {
    fun encryptAES(payload: String): String

    fun decryptAES(encryptedPayload: String): String
}
