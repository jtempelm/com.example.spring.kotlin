package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.EncryptedPayload
import com.example.spring.kotlin.dto.HybridEncryptedPayload
import com.example.spring.kotlin.util.CipherAlgorithm
import org.springframework.stereotype.Service
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8


@Service
class EncryptionServiceImpl : EncryptionService {

    private val AES_CIPHER = "AES/GCM/NoPadding"
    private val TAG_LENGTH_BITS = 128
    private val AES_IV_LENGTH_BYTES = 12

    private val TRIPLE_DES_CIPHER = "DESede/CBC/PKCS5Padding"
    private val DES_IV_LENGTH_BYTES = 8

    private val RSA_CRYPTO_BITS = 2048
    private val RSA_CIPHER = "RSA/ECB/PKCS1Padding" //RSA/ECB/OAEPWithSHA-512AndMGF1Padding not portable

    val base64EncodedSharedAppPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmAMTXnLy2BAZQw/trJSqYpO/e8VX7vzfJThQSV8KF3AMvllZ3qLSzRkFfhHPtlVGfBr3+aY42F2mPKy3x3wuc2QusRniMG2SXZ3vSABI63HUakLUZizwPK+HeW5L3bwf5UOFDJYr7oYkesBXjRapg5XFtrEpEarY0D8hYhHkeOJiPBCJ+dnjS+mq5OG9B+jj1FWrQzyUxqlZrU+Nv6idya8wmEGBvNNyGXbGbFT/fWo6Zgc8mdvhvU6gLup/RT4tI4LbslS/Gl7HtreQMS2Vr9kn7dlrZiLpD1szWC0ThFlXbOPz4PVDgT4+NG7grifbHO2isQCqqoum2YDS1NhPYQIDAQAB"

    val base64EncodedSharedAppSecretKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYAxNecvLYEBlDD+2slKpik797xVfu/N8lOFBJXwoXcAy+WVneotLNGQV+Ec+2VUZ8Gvf5pjjYXaY8rLfHfC5zZC6xGeIwbZJdne9IAEjrcdRqQtRmLPA8r4d5bkvdvB/lQ4UMlivuhiR6wFeNFqmDlcW2sSkRqtjQPyFiEeR44mI8EIn52eNL6ark4b0H6OPUVatDPJTGqVmtT42/qJ3JrzCYQYG803IZdsZsVP99ajpmBzyZ2+G9TqAu6n9FPi0jgtuyVL8aXse2t5AxLZWv2Sft2WtmIukPWzNYLROEWVds4/Pg9UOBPj40buCuJ9sc7aKxAKqqi6bZgNLU2E9hAgMBAAECggEAayJ3yzA+gRLPixk1zFU2xKUW5neOYuwrpQLMavmlliEtihZVJXkiEtTYryKEfyAYvi0Pqg6Br9RI7ihYmiqmXkM0OTNh2/nNl1dRJjC1M+MU7xNMuPphEpQvaeDXbV5CKIXuxpEsQz6dhTn8On7HV+r93qV7qWz8w8BKmeC8YoksWmIFPPSCaN3mnCVGaMI2NF/J1aX9OPZOBUV/6Jn2dntzokHd9nbatHmzmHxUx2pCw4byGQ0BmkXjn4ZxPzkvAVG8NHAdB2Rv/So75MIVru3QGX33EJiakgLetcDJrPjvn2rIauj7gKs7eQcVeoC06qPgS8cjs+73Dybs+ktchQKBgQDRik/lxqTCHJaOoqKSSZr7QJpuigg1ylvICPcK7LBDpPXNndhtmsT/T0Xp0n6HCRd0xCvVKTqzHdXgshQ5Ph4bubGMtdPe4cXNPUxI5feQnQKSDaHx7JY17UpkkfARR339TUiuE4xOCXu19k+8xXT6Sc4ddfCtXR99mrKolM5E+wKBgQC5t2jGCWs9DkSNo+wBSo7Ze1P69FI+2zTFqQEKBqSfPoN9wsihEe3O2RYyVgJ+IZokHZDnk2WUoU2x4lohLCQQF2n6UxSHkR5xpQUuR+FP6y9QdegdXJ6wiSnteHPwAowDobO86UZzBdNH2slvRC/V+1REqy8HsEYbUnKlwFE2UwKBgQDAgvVi4rzuRfug8hSwmAVWfwUjN5fRa6glQO9PTyOmEkFudm2oTUBeXEOcTjLG93hgY/btcWKnu2qLdLCV4tcgm9terpMIO59SL9YNR5LKfyYkb3fw328l/muRuG66QVekR8PVgsotzBKnm7OoeDU/2l0OvhOwA1VyPZWUwpo7zwKBgHLrpa/2IB/19kHXj7D03BSEFmGSUlqG9s7hV71GgxPvcRqfL9tL5uY6u1uGkaBPVrzGduZ19UPV1OggczlXwTEb6/507p09FaOpQ91xqWD03aBidbHFoIUJO6KxCL0aNl4A7+IUT/3ZOvaZ0lBB14AIOAsOCtotIBTEHiGnMhn1AoGAQ/axMpRkWNb4hTcCwY2IdNUTsvemyrtQX+0WKwYT5tpxuwTfb2Bo2QSTLyIZ0AlJHTm6zZL/BFvPjkW5lHuL/qA/xaVgzMEEUI0zOYHTcxnwrdoD39yjcAd4XCyPGNhGrOfFogKWTxJaVJeNn2mI3yrU2tr/eP/WABgBxa9D+0w="

    override fun generateBase64EncodedKey(length: Int): String {
        val secureRandom = SecureRandom()
        val key = ByteArray(length)
        secureRandom.nextBytes(key)

        return Base64.getEncoder().encodeToString(key)
    }

    override fun encryptAES(payload: String, encodedKey: String): EncryptedPayload {
        val secretKey = getAESSecretKey(encodedKey)
        val iv = generateInitializationVector(AES_IV_LENGTH_BYTES)

        val cipher = Cipher.getInstance(AES_CIPHER)
        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                GCMParameterSpec(TAG_LENGTH_BITS, iv)
        )

        val cipherBytes: ByteArray = cipher.doFinal(payload.toByteArray(UTF_8))

        //we encode the iv at the front of the cipherText message so it is packaged together for transit
        val byteBuffer = ByteBuffer.allocate(4 + iv.size + cipherBytes.size)
        byteBuffer.putInt(iv.size)
        byteBuffer.put(iv)
        byteBuffer.put(cipherBytes)

        val ivWithCipherBytes = byteBuffer.array()
        val encodedCipherText = Base64.getEncoder().encodeToString(ivWithCipherBytes)

        return EncryptedPayload(cipherText = encodedCipherText, iv = Base64.getEncoder().encodeToString(iv), key = encodedKey, algorithm = CipherAlgorithm.AES.cipher, keyPair = null)
    }

    private fun getAESSecretKey(encodedKey: String): SecretKeySpec {
        val decodedKey = Base64.getDecoder().decode(encodedKey)

        return SecretKeySpec(decodedKey, CipherAlgorithm.AES.cipher)
    }

    private fun generateInitializationVector(length: Int): ByteArray {
        val secureRandom = SecureRandom() //SecureRandom.getInstanceStrong() //wait for more entropy by invoking "strong" mode, but block the thread for a long time
        val iv = ByteArray(length)
        secureRandom.nextBytes(iv)

        return iv
    }

    override fun decryptAES(encryptedPayload: EncryptedPayload): String {
        val cipherBytes: ByteArray = Base64.getDecoder().decode(encryptedPayload.cipherText)
        val byteBuffer = ByteBuffer.wrap(cipherBytes)

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

        val secretKey = getAESSecretKey(encryptedPayload.key)
        val cipher = Cipher.getInstance(AES_CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, iv))

        return cipher.doFinal(cipherText).toString(UTF_8)
    }

    override fun encrypt3DES(payload: String, encodedKey: String): EncryptedPayload {
        val secretKey = get3DESecretKey(encodedKey)
        val iv = generateInitializationVector(DES_IV_LENGTH_BYTES)
        val ivParameterSpec = IvParameterSpec(iv)

        val cipher = Cipher.getInstance(TRIPLE_DES_CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)

        val plainTextBytes = payload.toByteArray(UTF_8)
        val encryptedTextBytes = cipher.doFinal(plainTextBytes)

        val cipherText = Base64.getEncoder().encodeToString(encryptedTextBytes)

        return EncryptedPayload(cipherText = cipherText, iv = Base64.getEncoder().encodeToString(iv), key = encodedKey, algorithm = CipherAlgorithm.DESede.cipher, keyPair = null)
    }

    private fun get3DESecretKey(encodedKey: String): SecretKey {
        val decodedKey = Base64.getDecoder().decode(encodedKey)
        val desKey = DESedeKeySpec(decodedKey)
        val secretKeyFactory: SecretKeyFactory = SecretKeyFactory.getInstance(CipherAlgorithm.DESede.cipher)

        return secretKeyFactory.generateSecret(desKey)
    }

    override fun decrypt3DES(encryptedPayload: EncryptedPayload): String {
        val secretKey = get3DESecretKey(encryptedPayload.key)

        val cipher = Cipher.getInstance(TRIPLE_DES_CIPHER)
        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                IvParameterSpec(
                        Base64.getDecoder().decode(encryptedPayload.iv)
                )
        )

        val cipherMessage: ByteArray = Base64.getDecoder().decode(encryptedPayload.cipherText)

        return cipher.doFinal(cipherMessage).toString(UTF_8)
    }

    override fun generateKeyPair(): KeyPair {
        val keypairGenerator = KeyPairGenerator.getInstance(CipherAlgorithm.RSA.cipher)

        keypairGenerator.initialize(RSA_CRYPTO_BITS)

        return keypairGenerator.genKeyPair()
    }

    override fun toPublicRSAKey(base64EncodedKey: String): PublicKey {
        val keyBytes: ByteArray = Base64.getDecoder().decode(base64EncodedKey)
        val spec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(CipherAlgorithm.RSA.cipher)

        return keyFactory.generatePublic(spec)
    }

    override fun toPrivateRSAKey(base64EncodedKey: String): PrivateKey {
        val keyBytes: ByteArray = Base64.getDecoder().decode(base64EncodedKey)
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(CipherAlgorithm.RSA.cipher)

        return keyFactory.generatePrivate(spec)
    }

    override fun encryptRSA(payload: String, keyPair: KeyPair): EncryptedPayload {
        val pubKey: PublicKey? = keyPair.public
        val cipher: Cipher = Cipher.getInstance(RSA_CIPHER)

        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        val encryptedBytes = cipher.doFinal(payload.toByteArray(UTF_8))

        val cipherText = Base64.getEncoder().encodeToString(encryptedBytes)

        return EncryptedPayload(cipherText = cipherText, iv = "", key = "", algorithm = CipherAlgorithm.RSA.cipher, keyPair = keyPair)
    }

    override fun decryptRSA(encryptedPayload: EncryptedPayload): String {
        val cipher: Cipher = Cipher.getInstance(RSA_CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, encryptedPayload.keyPair?.private)

        val cipherMessage: ByteArray = Base64.getDecoder().decode(encryptedPayload.cipherText)
        return cipher.doFinal(cipherMessage).toString(UTF_8)
    }

    override fun decryptHybridEncryptedPayload(hybridEncryptedPayload: HybridEncryptedPayload): String {
        val aesKey = decryptRSA(
                EncryptedPayload(
                        cipherText = hybridEncryptedPayload.encryptedKey,
                        iv = "",
                        key = "",
                        algorithm = CipherAlgorithm.RSA.cipher,
                        keyPair = getKeypair(base64EncodedSharedAppPublicKey, base64EncodedSharedAppSecretKey)
                )
        )

        return decryptAES(
                EncryptedPayload(
                        cipherText = hybridEncryptedPayload.encryptedPayload.cipherText,
                        iv = hybridEncryptedPayload.encryptedPayload.iv,
                        key = aesKey,
                        algorithm = CipherAlgorithm.AES.cipher,
                        keyPair = null
                )
        )
    }

    override fun getKeypair(base64EncodedPublicKey: String, base64EncodedPrivateKey: String): KeyPair {
        val publicKey = toPublicRSAKey(base64EncodedPublicKey)

        val privateKey = toPrivateRSAKey(base64EncodedPrivateKey)

        return KeyPair(publicKey, privateKey)
    }
}
