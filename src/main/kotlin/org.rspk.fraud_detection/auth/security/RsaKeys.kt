package com.fraudguard.auth.security

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64


object RsaKeys {

    fun generate(): RSAKey {
        /* both prime's combined will be 2048 so each prime is 1024 */
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        return toJwk(pair.public as RSAPublicKey, pair.private as RSAPrivateKey)
    }

    fun load(privateKeyPath: String, publicKeyPath: String): RSAKey {
        val factory = KeyFactory.getInstance("RSA")
        val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(readPem(privateKeyPath))) as RSAPrivateKey
        val publicKey = factory.generatePublic(X509EncodedKeySpec(readPem(publicKeyPath))) as RSAPublicKey
        return toJwk(publicKey, privateKey)
    }

    private fun toJwk(publicKey: RSAPublicKey, privateKey: RSAPrivateKey): RSAKey {
        val withoutId = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .build()
        return RSAKey.Builder(withoutId).keyID(withoutId.computeThumbprint().toString()).build()
    }

    private fun readPem(path: String): ByteArray {
        val base64 = Files.readAllLines(Path.of(path))
            .filterNot { it.startsWith("-----") }
            .joinToString("")
            .replace("\\s".toRegex(), "")
        return Base64.getDecoder().decode(base64)
    }
}
