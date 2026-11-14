package org.rspk.fraud_detection.auth.config

import com.fraudguard.auth.security.RsaKeys
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder

@Configuration(proxyBeanMethods = false)
class JwtKeyConfig {
    private val log = LoggerFactory.getLogger(JwtKeyConfig::class.java)

    @Bean
    fun signingKey(props: JwtProperties): RSAKey {
        return RsaKeys.generate()

        /*if (props.privateKeyPath.isNullOrBlank() || props.publicKeyPath.isNullOrBlank()) {
            log.warn(
                "No signing key configured: generated an EPHEMERAL RSA key. " +
                    "Tokens become invalid on restart. Use this for local development only.",
            )
        }
        return RsaKeys.load(props.privateKeyPath, props.publicKeyPath)*/
    }

    @Bean
    fun jwtEncoder(signingKey: RSAKey): JwtEncoder =
        NimbusJwtEncoder(ImmutableJWKSet<SecurityContext>(JWKSet(signingKey)))
}
