package com.example.spring.kotlin.controller

import com.example.spring.kotlin.dto.ApiStatusDto
import com.example.spring.kotlin.dto.ValueExchangeReferenceDto
import com.example.spring.kotlin.dto.ValueExchangeRequest
import com.example.spring.kotlin.model.ValueExchange
import com.example.spring.kotlin.service.ValueExchangeService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class ValueExchangeController() {

    @Autowired
    lateinit var valueExchangeService: ValueExchangeService

    @GetMapping("/status")
    fun status(): ResponseEntity<ApiStatusDto> {
        return ResponseEntity(ApiStatusDto(status = "ok"), HttpStatus.OK)
    }

    @PostMapping("/valueExchange")
    fun createValueExchange(@RequestBody valueExchangeRequest: ValueExchangeRequest): ResponseEntity<ValueExchangeReferenceDto> {
        return valueExchangeService.createValueExchange(valueExchangeRequest)
    }

    @GetMapping("/valueExchange/{id}")
    fun getValueExchange(@PathVariable id: Long): ResponseEntity<ValueExchange> {
        return valueExchangeService.getValueExchange(id)
    }
}