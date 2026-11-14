package org.rspk.fraud_detection.auth.controller

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.springframework.http.HttpStatus

/* Unit testing (checking input with correct output from the function) */
class BasicControllerTest {

    private val controller = BasicController()

    @Test
    fun `health check should return success message`() {
        val expectedResponse = "fraud authentication is active"

        val response = controller.healthCheck()

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedResponse, response.body)
    }
}