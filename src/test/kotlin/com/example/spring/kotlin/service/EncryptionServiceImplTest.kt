package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.EncryptedPayload
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

        val decryptedPayload = encryptionServiceImpl.decryptAES(EncryptedPayload(cipherText = cipherText, iv = "", key = base64EncodedTestKey, algorithm = "AES"))

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

        val decryptedPayload = encryptionServiceImpl.decrypt3DES(EncryptedPayload(cipherText = cipherText, iv = iv, key = base64EncodedTestKey, algorithm = "DESede"))
        assertEquals(decryptedPayload, "A pre-encrypted test string!")
    }

}
