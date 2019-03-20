package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.EncryptedPayload
import com.example.spring.kotlin.dto.HybridEncryptedPayload
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

interface EncryptionService {

    fun generateBase64EncodedKey(length: Int): String

    fun encryptAES(payload: String, encodedKey: String): EncryptedPayload

    fun decryptAES(encryptedPayload: EncryptedPayload): String

    fun encrypt3DES(payload: String, encodedKey: String): EncryptedPayload

    fun decrypt3DES(encryptedPayload: EncryptedPayload): String

    fun generateKeyPair(): KeyPair

    fun toPublicRSAKey(base64EncodedKey: String): PublicKey

    fun toPrivateRSAKey(base64EncodedKey: String): PrivateKey

    fun encryptRSA(payload: String, keyPair: KeyPair): EncryptedPayload

    fun decryptRSA(encryptedPayload: EncryptedPayload): String

    fun decryptHybridEncryptedPayload(hybridEncryptedPayload: HybridEncryptedPayload): String

    fun getKeypair(base64EncodedPublicKey: String, base64EncodedPrivateKey: String): KeyPair
}
