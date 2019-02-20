package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.EncryptedPayload
import com.example.spring.kotlin.dto.EncryptedPayloadRequest
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.dto.ValueExchangeRequest
import com.example.spring.kotlin.model.ValueExchange
import com.example.spring.kotlin.repository.ValueExchangeRepository
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service

@Service
class ValueExchangeServiceImpl : ValueExchangeService {

    private val logger = LoggerFactory.getLogger(this.javaClass.name)

    @Autowired
    lateinit var valueExchangeRepository: ValueExchangeRepository

    @Autowired
    lateinit var encryptionService: EncryptionService

    override fun getSystemStatus(): ResponseEntity<ApiStatusDto> {
        return ResponseEntity(ApiStatusDto(status = "ok"), HttpStatus.OK)
    }

    override fun createValueExchange(encryptedPayloadRequest: EncryptedPayloadRequest): ResponseEntity<ValueExchangeReferenceDto> {

        val mapper = jacksonObjectMapper()
        val valueExchangeRequest: ValueExchangeRequest

        try {
            val decryptedData = encryptionService.decryptAES(encryptedPayload = EncryptedPayload(cipherText = encryptedPayloadRequest.encryptedData, iv = "?TODO", key = "?TODO", algorithm = "?TODO"))
            valueExchangeRequest = mapper.readValue(decryptedData)
        } catch (exception: Exception) {
            logger.error("Error retrieving encrypted payload: ${exception.message}")
            throw exception
        }

        val valueExchange = valueExchangeRepository.save(
                ValueExchange(
                        id = -1,
                        merchantId = valueExchangeRequest.merchantId,
                        customerId = valueExchangeRequest.customerId,
                        currency = valueExchangeRequest.currency,
                        amount = valueExchangeRequest.amount,
                        productDescription = valueExchangeRequest.productDescription
                )
        )

        return ResponseEntity(ValueExchangeReferenceDto(id = valueExchange.id, status = "created"), HttpStatus.OK)
    }

    override fun getValueExchange(id: Long): ResponseEntity<ValueExchange> {
        val valueExchangeOptional = valueExchangeRepository.findById(id)
        if (!valueExchangeOptional.isPresent) {
            return ResponseEntity(HttpStatus.NOT_FOUND)
        }

        return ResponseEntity(valueExchangeOptional.get(), HttpStatus.NOT_FOUND)
    }
}
