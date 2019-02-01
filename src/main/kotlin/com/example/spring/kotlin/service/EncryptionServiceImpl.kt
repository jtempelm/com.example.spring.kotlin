package com.example.spring.kotlin.service

import org.springframework.stereotype.Service

@Service
class EncryptionServiceImpl : EncryptionService {
    override fun decryptAES(encryptedPayload: String): String {
        return encryptedPayload
    }

    override fun encryptAES(payload: String): String {
        return payload
    }
}
