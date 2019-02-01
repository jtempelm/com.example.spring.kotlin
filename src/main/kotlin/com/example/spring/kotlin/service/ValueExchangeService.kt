package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.EncryptedPayloadRequest
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.model.ValueExchange
import org.springframework.http.ResponseEntity

interface ValueExchangeService {
    fun getSystemStatus(): ResponseEntity<ApiStatusDto>

    fun createValueExchange(encryptedPayloadRequest: EncryptedPayloadRequest): ResponseEntity<ValueExchangeReferenceDto>

    fun getValueExchange(id: Long): ResponseEntity<ValueExchange> //TODO encrypt before sending to client

}
