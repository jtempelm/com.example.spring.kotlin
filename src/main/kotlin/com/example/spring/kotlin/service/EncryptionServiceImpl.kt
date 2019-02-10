package com.example.spring.kotlin.service

import org.springframework.stereotype.Service
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8


@Service
class EncryptionServiceImpl : EncryptionService {

    val TAG_LENGTH_BIT = 128

    override fun generateBase64EncodedAESKey(): String {
        val secureRandom = SecureRandom()
        val key = ByteArray(16)
        secureRandom.nextBytes(key)

        return Base64.getEncoder().encodeToString(key)
    }

    override fun encryptAES(payload: String, encodedKey: String): String {
        val secretKey = getAESSecretKey(encodedKey)
        val iv = generateInitializationVector()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BIT, iv))

        val cipherText: ByteArray = cipher.doFinal(payload.toByteArray(UTF_8))

        //we encode the iv at the front of the cipherText message so it is packaged together for transit
        val byteBuffer = ByteBuffer.allocate(4 + iv.size + cipherText.size)
        byteBuffer.putInt(iv.size)
        byteBuffer.put(iv)
        byteBuffer.put(cipherText)

        val cipherMessage = byteBuffer.array()
        return Base64.getEncoder().encodeToString(cipherMessage)
    }

    private fun getAESSecretKey(encodedKey: String): SecretKeySpec {
        val decodedKey = Base64.getDecoder().decode(encodedKey)

        return SecretKeySpec(decodedKey, "AES")
    }

    private fun generateInitializationVector(): ByteArray {
        val secureRandom = SecureRandom()
        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)

        return iv
    }

    override fun decryptAES(encryptedPayload: String, encodedKey: String): String {
        val cipherMessage: ByteArray = Base64.getDecoder().decode(encryptedPayload)
        val byteBuffer = ByteBuffer.wrap(cipherMessage)

        //validate iv length matches int size
        val ivLength = byteBuffer.int
        if (ivLength < 12 || ivLength >= 16) {
            throw IllegalArgumentException("invalid iv length")
        }

        //fetch iv from the start of the cipherText
        val iv = ByteArray(ivLength)
        byteBuffer.get(iv)

        //fetch the actual message from the remaining cipherText
        val cipherText = ByteArray(byteBuffer.remaining())
        byteBuffer.get(cipherText)

        val secretKey = getAESSecretKey(encodedKey)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BIT, iv))

        return cipher.doFinal(cipherText).toString(UTF_8)
    }

}
