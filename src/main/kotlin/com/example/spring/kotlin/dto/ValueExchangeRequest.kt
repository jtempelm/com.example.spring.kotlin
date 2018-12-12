package com.example.spring.kotlin.dto

data class ValueExchangeRequest(
        val merchantId: Long,
        val customerId: Long,
        val currency: String,
        val amount: String,
        val productDescription: String)

