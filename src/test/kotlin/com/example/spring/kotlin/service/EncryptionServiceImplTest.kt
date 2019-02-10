package com.example.spring.kotlin.service

import org.apache.tomcat.util.codec.binary.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptionServiceImplTest {

    private val encryptionServiceImpl: EncryptionService = EncryptionServiceImpl()

    @Test
    fun testEncryptAESReturnsBase64() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedAESKey()

        val testString = "This is a test string that we want to encrypt with AES"

        val encryptedPayload = encryptionServiceImpl.encryptAES(testString, encodedKey)

        assertTrue(Base64.isBase64(encryptedPayload))
    }

    @Test
    fun testEncryptAndDecryptAESResultsInSamePlainText() {
        val encodedKey = encryptionServiceImpl.generateBase64EncodedAESKey()

        val testString = "This is a test string that will be unchanged with encryption and then decryption"

        val encryptedPayload = encryptionServiceImpl.encryptAES(testString, encodedKey)
        assertTrue(Base64.isBase64(encryptedPayload))

        val decryptedPayload = encryptionServiceImpl.decryptAES(encryptedPayload, encodedKey)
        assertEquals(testString, decryptedPayload)
    }

    @Test
    fun testDecryptAES() {
        val base64EncodedTestKey = "iL9AEgIHHW/MtoGrnPsBeg=="
        val encryptedPayload = "AAAADE5VXI3hUfGpG91iMSjl8jjrSW+saJDv0TA/f/wgsj88UNIJWBrzdoDrXc5eO5tBGz46uKtCkyhQ"

        val decryptedPayload = encryptionServiceImpl.decryptAES(encryptedPayload, base64EncodedTestKey)
        assertEquals(decryptedPayload, "A pre-encrypted test string!")
    }

}
