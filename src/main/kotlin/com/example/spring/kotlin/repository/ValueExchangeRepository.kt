package com.example.spring.kotlin.repository

import com.example.spring.kotlin.model.ValueExchange
import org.springframework.data.repository.CrudRepository

interface ValueExchangeRepository : CrudRepository<ValueExchange, Long> {

    fun findAllByMerchantId(merchantId: Long): List<ValueExchange>

    fun findAllByCustomerId(customerId: Long): List<ValueExchange>

}