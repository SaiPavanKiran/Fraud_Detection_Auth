package org.rspk.fraud_detection.auth.service

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll
import org.junit.jupiter.api.assertNotNull
import org.mockito.ArgumentMatchers
import org.rspk.fraud_detection.auth.repository.UserAccountsRepo
import org.springframework.security.crypto.password.PasswordEncoder
import org.mockito.kotlin.*
import org.rspk.fraud_detection.auth.config.JwtProperties
import org.rspk.fraud_detection.auth.model.AuthUser
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Optional
import java.util.UUID

class AuthServiceTest {

    @Test
    fun `should generate valid JWT with expected claims`() {
        // Arrange
        val rsaKey = RSAKeyGenerator(2048)
            .keyID("test-key-1")
            .generate()
        val encoder = NimbusJwtEncoder(
            ImmutableJWKSet<SecurityContext> (
                JWKSet(rsaKey)
            )
        )

        val properties = JwtProperties(
            issuer = "fraud-auth-service",
            audience = "fraud-api",
            accessTokenTtl = Duration.ofMinutes(30)
        )

        val fixedTime = Instant.parse(
            "2026-11-10T10:00:00Z"
        )

        val clock = Clock.fixed(
            fixedTime,
            ZoneOffset.UTC
        )

        val service = AuthService(
            jwtEncoder = encoder,
            signingKey = rsaKey,
            props = properties,
            clock = clock
        )

        val user = AuthUser(
            username = "john",
            passwordHash = "encoded"
        )

        val userId = UUID.randomUUID()

        // Act
        val token = service.issueAccessToken(
            user.apply {
                setId(userId)
            }
        )


        // Assert
        assertNotNull(token.value)
        assertEquals(1800L, token.expiresInSeconds)
    }
}