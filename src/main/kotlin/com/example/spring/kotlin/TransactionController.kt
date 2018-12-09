package com.example.spring.kotlin

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TransactionController {

//    List inMemoryTransactions = List();

    @GetMapping("/status")
    fun status(): ApiStatus {
        return ApiStatus(status = "ok")
    }

    @PostMapping("/transaction")
    fun createTransaction(): ApiStatus {
        return ApiStatus(status = "ok")
    }

    @GetMapping("/transaction")
    fun getTransaction(): ApiStatus {
        return ApiStatus(status = "ok")
    }
}