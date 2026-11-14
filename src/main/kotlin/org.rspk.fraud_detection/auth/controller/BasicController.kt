package org.rspk.fraud_detection.auth.controller

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class BasicController {


    @GetMapping("/health")
    fun healthCheck(): ResponseEntity<Any> {
        return ResponseEntity.ok("fraud authentication is active")
    }


}