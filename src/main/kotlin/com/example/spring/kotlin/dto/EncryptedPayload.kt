package com.example.spring.kotlin.dto

data class EncryptedPayload(val cipherText: String, val iv: String, val key: String, val algorithm: String)
