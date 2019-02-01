package com.example.spring.kotlin.interceptor

import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.servlet.HandlerInterceptor
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class SecurityInterceptor : HandlerInterceptor {

    private val logger = LoggerFactory.getLogger(this.javaClass.name)

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, dataObject: Any): Boolean {
        logger.info("Received request from ${request.remoteAddr} to ${request.requestURI}")
        return true
    }

    override fun postHandle(request: HttpServletRequest, response: HttpServletResponse, dataObject: Any, model: ModelAndView?) {
        logger.info("Response code was ${response.status}")
    }

    override fun afterCompletion(request: HttpServletRequest, response: HttpServletResponse, dataObject: Any, e: Exception?) {
        if (e != null) {
            logger.error(e.message)

        }
        val string = "{\n" +
                "        \"merchantId\": 1,\n" +
                "        \"customerId\": 1,\n" +
                "        \"currency\": \"USD\",\n" +
                "        \"amount\": \"5.00\",\n" +
                "        \"productDescription\": \"Pack of socks\"\n" +
                "    }"
    }
}