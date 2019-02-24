package com.example.spring.kotlin.dto

import java.security.KeyPair

data class EncryptedPayload(val cipherText: String, val iv: String, val key: String, val algorithm: String, val keyPair: KeyPair?)
