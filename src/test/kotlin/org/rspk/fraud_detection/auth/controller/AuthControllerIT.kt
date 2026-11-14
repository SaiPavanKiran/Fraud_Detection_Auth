package org.rspk.fraud_detection.auth.controller

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import org.rspk.fraud_detection.auth.IntegrationTestBase
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status


class AuthControllerIT : IntegrationTestBase() {


    @Test
    fun `should successfully register a new user`() {

        mockMvc.perform(
            post("/auth/sign-up")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "StrongPassword123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.username").value("john"))
            .andExpect(jsonPath("$.created_at").exists())
    }


    @Test
    fun `should reject duplicate username`() {

        registerUser("john", "Password123!")

        mockMvc.perform(
            post("/auth/sign-up")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "AnotherPassword123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().is4xxClientError)
    }


    @Test
    fun `should reject blank username`() {

        mockMvc.perform(
            post("/auth/sign-up")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "",
                        "password": "Password123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    @Test
    fun `should reject blank password`() {

        mockMvc.perform(
            post("/auth/sign-up")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": ""
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    @Test
    fun `should reject query parameters during registration`() {

        mockMvc.perform(
            post("/auth/sign-up?username=john")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "Password123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    @Test
    fun `should successfully authenticate registered user`() {

        registerUser("john", "Password123!")

        mockMvc.perform(
            post("/auth/sign-in")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "Password123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.access_token").isNotEmpty)
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.expires_in").value(1800))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(header().string("Pragma", "no-cache"))
    }

    @Test
    fun `should reject incorrect password`() {

        registerUser("john", "Password123!")

        mockMvc.perform(
            post("/auth/sign-in")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "WrongPassword123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun `should reject authentication for nonexistent user`() {

        mockMvc.perform(
            post("/auth/sign-in")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "unknown",
                        "password": "Password123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_grant"))
    }

    @Test
    fun `should reject blank credentials during sign in`() {

        mockMvc.perform(
            post("/auth/sign-in")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "",
                        "password": ""
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
    }

    @Test
    fun `should not expose token in cacheable response`() {

        registerUser("john", "Password123!")

        val result = mockMvc.perform(
            post("/auth/sign-in")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "john",
                        "password": "Password123!"
                    }
                    """.trimIndent()
                )
        )
            .andExpect(status().isOk)
            .andReturn()

        assertEquals(
            "no-store",
            result.response.getHeader("Cache-Control")
        )

        assertEquals(
            "no-cache",
            result.response.getHeader("Pragma")
        )

        assertNotNull(result.response.contentAsString)
    }



    private fun registerUser(username: String, password: String) {
        mockMvc.perform(
            post("/auth/sign-up")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {
                        "username": "$username",
                        "password": "$password"
                    }
                    """.trimIndent()
                )
        ).andExpect(status().isOk)
    }

}