package com.example.spring.kotlin.service

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.dto.ValueExchangeRequest
import com.example.spring.kotlin.model.ValueExchange
import com.example.spring.kotlin.repository.ValueExchangeRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service

@Service
class ValueExchangeServiceImpl : ValueExchangeService {

    override fun getSystemStatus(): ResponseEntity<ApiStatusDto> {
        return ResponseEntity(ApiStatusDto(status = "ok"), HttpStatus.OK)
    }

    @Autowired
    lateinit var valueExchangeRepository: ValueExchangeRepository

    override fun createValueExchange(valueExchangeRequest: ValueExchangeRequest): ResponseEntity<ValueExchangeReferenceDto> {
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
