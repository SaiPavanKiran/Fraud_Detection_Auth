package org.rspk.fraud_detection.auth.controller

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.http.CacheControl
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.util.concurrent.TimeUnit

/** Publishes PUBLIC keys only (RFC 7517), so resource servers can verify tokens without any shared secret. */
@RestController
class JwksController(
    private val signingKey: RSAKey,
) {
    @GetMapping("/.well-known/jwks.json")
    fun jwks(): ResponseEntity<Map<String, Any>> =
        ResponseEntity.ok()
            .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES).cachePublic())
            .body(JWKSet(signingKey.toPublicJWK()).toJSONObject())
}
