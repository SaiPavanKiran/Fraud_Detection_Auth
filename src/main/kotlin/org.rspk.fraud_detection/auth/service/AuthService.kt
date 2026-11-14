package org.rspk.fraud_detection.auth.service

import org.rspk.fraud_detection.auth.config.JwtProperties
import org.rspk.fraud_detection.auth.model.AuthUser
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

data class IssuedToken(val value: String, val expiresInSeconds: Long)

@Service
class AuthService(
    private val jwtEncoder: JwtEncoder,
    private val signingKey: RSAKey,
    private val props: JwtProperties,
    private val clock: Clock,
) {
    @Transactional
    fun issueAccessToken(user: AuthUser): IssuedToken {
        val issuedAt = Instant.now(clock).truncatedTo(ChronoUnit.SECONDS)
        val expiresAt = issuedAt.plus(props.accessTokenTtl)

        val claims = JwtClaimsSet.builder()
            .issuer(props.issuer)
            .subject(user.id.toString())
            .audience(listOf(props.audience))
            .issuedAt(issuedAt)
            .expiresAt(expiresAt)
            .id(UUID.randomUUID().toString())
            .build()

        /*keyId :- used to identify key from multiple rsa keys*/
        val header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(signingKey.keyID).build()
        val token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue

        return IssuedToken(token, props.accessTokenTtl.seconds)
    }

}
