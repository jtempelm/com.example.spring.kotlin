package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.HybridEncryptedPayload
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.model.ValueExchange
import org.springframework.http.ResponseEntity

interface ValueExchangeService {
    fun getSystemStatus(): ResponseEntity<ApiStatusDto>

    fun createValueExchange(hybridEncryptedPayload: HybridEncryptedPayload): ResponseEntity<ValueExchangeReferenceDto>

    fun getValueExchange(id: Long): ResponseEntity<ValueExchange> //TODO encrypt before sending to client

}
