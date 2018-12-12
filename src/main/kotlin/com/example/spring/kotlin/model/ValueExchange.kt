package com.example.spring.kotlin.model

import java.time.Instant
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.Table

@Entity
@Table(name = "value_exchange")
class ValueExchange(

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        val id: Long,

        @Column(name = "merchant_id")
        val merchantId: Long,

        @Column(name = "customer_id")
        val customerId: Long,

        @Column(name = "currency")
        val currency: String,

        @Column(name = "amount")
        val amount: String,

        @Column(name = "product_desc")
        val productDescription: String = "",

        @Column(name = "date")
        val date: Instant = Instant.now()


) {
    override fun toString(): String {
        return "ValueExchange(id=$id, merchantId=$merchantId, customerId=$customerId, currency=$currency, amount=$amount, productDescription='$productDescription', date=$date)"
    }
}