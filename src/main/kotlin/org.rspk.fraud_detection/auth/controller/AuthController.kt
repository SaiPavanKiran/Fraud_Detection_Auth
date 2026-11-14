package org.rspk.fraud_detection.auth.controller

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonProperty
import org.rspk.fraud_detection.auth.exception.JWTErrors
import org.rspk.fraud_detection.auth.exception.JWTException
import org.rspk.fraud_detection.auth.service.AuthenticationService
import jakarta.servlet.http.HttpServletRequest
import org.rspk.fraud_detection.auth.service.AuthService
import org.slf4j.LoggerFactory
import org.springframework.http.CacheControl
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/** Success response per RFC 6749 section 5.1. */
data class TokenResponse(
    @get:JsonProperty("access_token") val accessToken: String,
    @get:JsonProperty("token_type") val tokenType: String,
    @get:JsonProperty("expires_in") val expiresIn: Long
)

data class UserAccount(
    @get:JsonProperty("username") val username: String,
    @get:JsonProperty("created_at")
    @get:JsonFormat(
        shape = JsonFormat.Shape.STRING,
        pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
        timezone = "UTC"
    )
    val createdAT: Instant
)

data class UserCredentials(
    val username: String,
    val password: String
)

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authenticationService: AuthenticationService,
    private val authService: AuthService,
) {
    private val log = LoggerFactory.getLogger(AuthController::class.java)

    @PostMapping("/sign-in", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun generateToken(
        @RequestBody credentials: UserCredentials,
        request: HttpServletRequest,
    ): ResponseEntity<TokenResponse> {
        val username = credentials.username
        val password = credentials.password

        if (request.queryString != null) {
            throw JWTException(JWTErrors.INVALID_REQUEST, "Parameters must be sent in the request body, not the URL")
        }
        if (username.isBlank() || password.isBlank()) {
            throw JWTException(JWTErrors.INVALID_REQUEST, "username and password are required")
        }

        val user = authenticationService.authenticate(username, password)
            ?: throw JWTException(JWTErrors.INVALID_GRANT, "Invalid username or password")

        val issued = authService.issueAccessToken(user)
        log.info("JWT token issued userId={}", user.id)

        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore()) // RFC 6749: token responses must not be cached
            .header("Pragma", "no-cache")
            .body(TokenResponse(issued.value, "Bearer", issued.expiresInSeconds))
    }


    @PostMapping("/sign-up",  consumes = [MediaType.APPLICATION_JSON_VALUE] )
    fun signUp(
        @RequestBody credentials: UserCredentials,
        request: HttpServletRequest
    ) : ResponseEntity<Any> {
        val username = credentials.username
        val password = credentials.password

        if (request.queryString != null) {
            throw JWTException(JWTErrors.INVALID_REQUEST, "Parameters must be sent in the request body, not the URL")
        }

        if (username.isBlank() || password.isBlank()) {
            throw JWTException(JWTErrors.INVALID_REQUEST, "username and password are required")
        }

        val user = authenticationService.createAccount(username,password)
            ?: throw JWTException(JWTErrors.INVALID_REQUEST, "User already exists or invalid request")

        log.info("User has been created with id {} and email {}",user.id,user.username)

        return ResponseEntity.ok(UserAccount(user.username,user.creationAt!!))
    }



}
