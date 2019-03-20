package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.EncryptedPayload
import com.example.spring.kotlin.util.CipherAlgorithm
import org.apache.tomcat.util.codec.binary.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptionServiceImplTest {

    private val encryptionServiceImpl: EncryptionService = EncryptionServiceImpl()

    private val AES_KEY_LENGTH_BYTES = 16 //128 bit key, AES is 128, 192 and 256

    private val DESede_KEY_LENGTH_BITS = 24

    @Test
    fun testEncryptAESReturnsBase64() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedKey(AES_KEY_LENGTH_BYTES)
        val testString = "This is a test string that we want to encrypt with AES"
        val encryptedPayload = encryptionServiceImpl.encryptAES(testString, encodedKey)

        assertTrue(Base64.isBase64(encryptedPayload.cipherText))
    }

    @Test
    fun testEncryptAndDecryptAESResultsInSamePlainText() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedKey(AES_KEY_LENGTH_BYTES)
        val testString = "This is a test string that will be unchanged with encryption and then decryption"

        val encryptedPayload = encryptionServiceImpl.encryptAES(testString, encodedKey)

        assertNotNull(encryptedPayload.cipherText)
        assertTrue(Base64.isBase64(encryptedPayload.cipherText))

        assertNotNull(encryptedPayload.iv) //iv is set in the cipherText, so we do not need it here, technically
        assertTrue(Base64.isBase64(encryptedPayload.iv))

        assertNotNull(encryptedPayload.key)
        assertTrue(Base64.isBase64(encryptedPayload.key))

        val decryptedPayload = encryptionServiceImpl.decryptAES(encryptedPayload)
        assertEquals(testString, decryptedPayload)
    }

    @Test
    fun testDecryptAES() {
        val cipherText = "AAAADE5VXI3hUfGpG91iMSjl8jjrSW+saJDv0TA/f/wgsj88UNIJWBrzdoDrXc5eO5tBGz46uKtCkyhQ"
        val base64EncodedTestKey = "iL9AEgIHHW/MtoGrnPsBeg=="

        val decryptedPayload = encryptionServiceImpl.decryptAES(EncryptedPayload(cipherText = cipherText, iv = "", key = base64EncodedTestKey, algorithm = CipherAlgorithm.AES.cipher, keyPair = null))

        assertEquals(decryptedPayload, "A pre-encrypted test string!")
    }

    @Test
    fun testEncrypt3DESReturnsBase64() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedKey(DESede_KEY_LENGTH_BITS)

        val testString = "This is a test string that we want to encrypt with 3DES"

        val encryptedPayload = encryptionServiceImpl.encrypt3DES(testString, encodedKey)

        assertTrue(Base64.isBase64(encryptedPayload.cipherText))
        assertNotNull(Base64.isBase64(encryptedPayload.iv))
        assertTrue(Base64.isBase64(encryptedPayload.iv))
    }

    @Test
    fun testEncryptAndDecrypt3DESResultsInSamePlainText() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedKey(DESede_KEY_LENGTH_BITS)

        val testString = "A pre-encrypted test string!"

        val encryptedPayload = encryptionServiceImpl.encrypt3DES(testString, encodedKey)

        assertNotNull(encryptedPayload.cipherText)
        assertTrue(Base64.isBase64(encryptedPayload.cipherText))

        assertNotNull(encryptedPayload.iv)
        assertTrue(Base64.isBase64(encryptedPayload.iv))

        assertNotNull(encryptedPayload.key)
        assertTrue(Base64.isBase64(encryptedPayload.key))

        val decryptedPayload = encryptionServiceImpl.decrypt3DES(encryptedPayload)
        assertEquals(testString, decryptedPayload)
    }

    @Test
    fun testDecrypt3DES() {
        val base64EncodedTestKey = "l7Torf2Bom+fv3MsWn6Nbw7uGln8bjVm"
        val cipherText = "CMZlH4qfEaE72/gvpNXT3N1qXw39oehX39E50RVCL0Q="
        val iv = "PefjUUy2fjM="

        val decryptedPayload = encryptionServiceImpl.decrypt3DES(EncryptedPayload(cipherText = cipherText, iv = iv, key = base64EncodedTestKey, algorithm = CipherAlgorithm.DESede.cipher, keyPair = null))
        assertEquals(decryptedPayload, "A pre-encrypted test string!")
    }

    @Test
    fun testEncryptRSAReturnsBase64() {
        val keyPair = encryptionServiceImpl.generateKeyPair()
        val testString = "This is a test string that we want to encrypt with RSA"
        val encryptedPayload = encryptionServiceImpl.encryptRSA(testString, keyPair)

        assertTrue(Base64.isBase64(encryptedPayload.cipherText))
    }

    @Test
    fun testEncryptAndDecryptRSAResultsInSamePlainText() {
        val keyPair = encryptionServiceImpl.generateKeyPair()
        val testString = "This is a test string that will be unchanged with encryption and then decryption"

        val encryptedPayload = encryptionServiceImpl.encryptRSA(testString, keyPair)

        assertNotNull(encryptedPayload.cipherText)
        assertTrue(Base64.isBase64(encryptedPayload.cipherText))

        assertNotNull(encryptedPayload.iv) //iv is set in the cipherText, so we do not need it here, technically
        assertTrue(Base64.isBase64(encryptedPayload.iv))

        assertNotNull(encryptedPayload.key)
        assertTrue(Base64.isBase64(encryptedPayload.key))

        val decryptedPayload = encryptionServiceImpl.decryptRSA(encryptedPayload)
        assertEquals(testString, decryptedPayload)
    }

    @Test
    fun testDecryptRSA() {
        val cipherText = "lRQ/PSP8bNNVTeGPq4kWpx73A4IytMHvEcXlfxQJtj0ETQxu0s3twPgdQkDJjGPLfeZQe29t7gjR2BB5L6iHAhYsNGzjoLy+DjWSWEx9DILb7DJ3DS5L6qbTT0bgYBd5fWJfhEjbYdz3B+ckXW48q2IzkcoDI7Am/cSYOjUdAX3qMHB4C8bmcGMhwx5sEpQq2G7UysXmNBPAPf3QcCrl40PLfN2OqGyq+b9T5ZFhgMzp9FqOqiEattmfH9ohW4LwBl1PBphw3KlF6qL4VE1s+U9gkWQK24deVITIGuwvZV9GyRfnMC6mr987JdKe1Th5z8dG61VEAf2muf4rX+w24Q=="

        val base64EncodedPublicTestKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmAMTXnLy2BAZQw/trJSqYpO/e8VX7vzfJThQSV8KF3AMvllZ3qLSzRkFfhHPtlVGfBr3+aY42F2mPKy3x3wuc2QusRniMG2SXZ3vSABI63HUakLUZizwPK+HeW5L3bwf5UOFDJYr7oYkesBXjRapg5XFtrEpEarY0D8hYhHkeOJiPBCJ+dnjS+mq5OG9B+jj1FWrQzyUxqlZrU+Nv6idya8wmEGBvNNyGXbGbFT/fWo6Zgc8mdvhvU6gLup/RT4tI4LbslS/Gl7HtreQMS2Vr9kn7dlrZiLpD1szWC0ThFlXbOPz4PVDgT4+NG7grifbHO2isQCqqoum2YDS1NhPYQIDAQAB"

        val base64EncodedPrivateTestKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYAxNecvLYEBlDD+2slKpik797xVfu/N8lOFBJXwoXcAy+WVneotLNGQV+Ec+2VUZ8Gvf5pjjYXaY8rLfHfC5zZC6xGeIwbZJdne9IAEjrcdRqQtRmLPA8r4d5bkvdvB/lQ4UMlivuhiR6wFeNFqmDlcW2sSkRqtjQPyFiEeR44mI8EIn52eNL6ark4b0H6OPUVatDPJTGqVmtT42/qJ3JrzCYQYG803IZdsZsVP99ajpmBzyZ2+G9TqAu6n9FPi0jgtuyVL8aXse2t5AxLZWv2Sft2WtmIukPWzNYLROEWVds4/Pg9UOBPj40buCuJ9sc7aKxAKqqi6bZgNLU2E9hAgMBAAECggEAayJ3yzA+gRLPixk1zFU2xKUW5neOYuwrpQLMavmlliEtihZVJXkiEtTYryKEfyAYvi0Pqg6Br9RI7ihYmiqmXkM0OTNh2/nNl1dRJjC1M+MU7xNMuPphEpQvaeDXbV5CKIXuxpEsQz6dhTn8On7HV+r93qV7qWz8w8BKmeC8YoksWmIFPPSCaN3mnCVGaMI2NF/J1aX9OPZOBUV/6Jn2dntzokHd9nbatHmzmHxUx2pCw4byGQ0BmkXjn4ZxPzkvAVG8NHAdB2Rv/So75MIVru3QGX33EJiakgLetcDJrPjvn2rIauj7gKs7eQcVeoC06qPgS8cjs+73Dybs+ktchQKBgQDRik/lxqTCHJaOoqKSSZr7QJpuigg1ylvICPcK7LBDpPXNndhtmsT/T0Xp0n6HCRd0xCvVKTqzHdXgshQ5Ph4bubGMtdPe4cXNPUxI5feQnQKSDaHx7JY17UpkkfARR339TUiuE4xOCXu19k+8xXT6Sc4ddfCtXR99mrKolM5E+wKBgQC5t2jGCWs9DkSNo+wBSo7Ze1P69FI+2zTFqQEKBqSfPoN9wsihEe3O2RYyVgJ+IZokHZDnk2WUoU2x4lohLCQQF2n6UxSHkR5xpQUuR+FP6y9QdegdXJ6wiSnteHPwAowDobO86UZzBdNH2slvRC/V+1REqy8HsEYbUnKlwFE2UwKBgQDAgvVi4rzuRfug8hSwmAVWfwUjN5fRa6glQO9PTyOmEkFudm2oTUBeXEOcTjLG93hgY/btcWKnu2qLdLCV4tcgm9terpMIO59SL9YNR5LKfyYkb3fw328l/muRuG66QVekR8PVgsotzBKnm7OoeDU/2l0OvhOwA1VyPZWUwpo7zwKBgHLrpa/2IB/19kHXj7D03BSEFmGSUlqG9s7hV71GgxPvcRqfL9tL5uY6u1uGkaBPVrzGduZ19UPV1OggczlXwTEb6/507p09FaOpQ91xqWD03aBidbHFoIUJO6KxCL0aNl4A7+IUT/3ZOvaZ0lBB14AIOAsOCtotIBTEHiGnMhn1AoGAQ/axMpRkWNb4hTcCwY2IdNUTsvemyrtQX+0WKwYT5tpxuwTfb2Bo2QSTLyIZ0AlJHTm6zZL/BFvPjkW5lHuL/qA/xaVgzMEEUI0zOYHTcxnwrdoD39yjcAd4XCyPGNhGrOfFogKWTxJaVJeNn2mI3yrU2tr/eP/WABgBxa9D+0w="

        val keyPair = encryptionServiceImpl.getKeypair(base64EncodedPublicTestKey, base64EncodedPrivateTestKey)

        val decryptedPayload = encryptionServiceImpl.decryptRSA(EncryptedPayload(cipherText = cipherText, iv = "", key = "", algorithm = CipherAlgorithm.RSA.cipher, keyPair = keyPair))

        assertEquals(decryptedPayload, "A pre-encrypted test string!")
    }

}
