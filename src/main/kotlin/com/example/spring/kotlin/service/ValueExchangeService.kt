package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.dto.ValueExchangeRequest
import com.example.spring.kotlin.model.ValueExchange
import org.springframework.http.ResponseEntity

interface ValueExchangeService {
    fun getSystemStatus(): ResponseEntity<ApiStatusDto>

    fun createValueExchange(valueExchangeRequest: ValueExchangeRequest): ResponseEntity<ValueExchangeReferenceDto>

    fun getValueExchange(id: Long): ResponseEntity<ValueExchange>

}
