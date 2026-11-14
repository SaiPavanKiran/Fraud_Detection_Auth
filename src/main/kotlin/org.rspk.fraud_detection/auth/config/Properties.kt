package org.rspk.fraud_detection.auth.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "app.jwt")
data class JwtProperties(
    val issuer: String,
    val audience: String,
    val accessTokenTtl: Duration = Duration.ofMinutes(30),
)
