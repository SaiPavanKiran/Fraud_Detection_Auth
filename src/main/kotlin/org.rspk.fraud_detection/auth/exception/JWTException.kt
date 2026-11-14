package org.rspk.fraud_detection.auth.exception

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.CacheControl
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice


object JWTErrors {
    const val INVALID_REQUEST = "invalid_request"
    const val INVALID_GRANT = "invalid_grant"
    const val INVALID_SCOPE = "invalid_scope"
    const val UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
}

class JWTException(
    val error: String,
    val description: String,
    val status: HttpStatus = HttpStatus.BAD_REQUEST,
) : RuntimeException(description)

data class JWTErrorResponse(
    @get:JsonProperty("error") val error: String,
    @get:JsonProperty("error_description") val errorDescription: String,
)

@RestControllerAdvice
class JWTExceptionHandler {
    @ExceptionHandler(JWTException::class)
    fun handle(ex: JWTException): ResponseEntity<JWTErrorResponse> =
        ResponseEntity.status(ex.status)
            /*It instructs browsers and intermediate caches not to store the response.*/
            .cacheControl(CacheControl.noStore())
            /*Pragma: no-cache is an older HTTP/1.0 compatibility mechanism.*/
            .header("Pragma", "no-cache")
            .body(JWTErrorResponse(ex.error, ex.description))
}
