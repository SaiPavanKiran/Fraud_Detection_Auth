package org.rspk.fraud_detection.auth.controller

import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.rspk.fraud_detection.auth.model.AuthUser
import org.rspk.fraud_detection.auth.service.AuthService
import org.rspk.fraud_detection.auth.service.AuthenticationService
import org.rspk.fraud_detection.auth.service.IssuedToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

/*MVC unit tests*/
@WebMvcTest(AuthController::class)
class AuthControllerTest {

    @Autowired
    lateinit var mockMvc: MockMvc

    @MockitoBean
    lateinit var authenticationService: AuthenticationService

    @MockitoBean
    lateinit var authService: AuthService


    @Test
    fun `sign in should return access token`() {


        // Arrange
        val user = AuthUser(
            username = "john",
            passwordHash = "encoded"
        )

        whenever(
            authenticationService.authenticate(
                "john",
                "password123"
            )
        ).thenReturn(user)

        whenever(authService.issueAccessToken(user))
            .thenReturn(
                IssuedToken(
                    "test.jwt.token",
                    1800
                )
            )

        //act + assert
        mockMvc.post("/auth/sign-in") {
            contentType = MediaType.APPLICATION_JSON
            content = """
            {
                "username": "john",
                "password": "password123"
            }
            """.trimIndent()

        }.andExpect {
            status { isOk() }
            content { contentType(MediaType.APPLICATION_JSON) }
            jsonPath("$.access_token") {
                value("test.jwt.token")
            }

            jsonPath("$.token_type") {
                value("Bearer")
            }

            jsonPath("$.expires_in") {
                value(1800)
            }

            header {
                string("Pragma", "no-cache")
            }
        }

        verify(authenticationService).authenticate("john", "password123")
        verify(authService).issueAccessToken(user)
    }
}