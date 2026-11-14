package org.rspk.fraud_detection.auth.service

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
import org.rspk.fraud_detection.auth.model.AuthUser
import org.slf4j.LoggerFactory
import java.util.Optional


class AuthenticationServiceTest {

    private lateinit var users: UserAccountsRepo
    private lateinit var passwordEncoder: PasswordEncoder
    private lateinit var service: AuthenticationService
    private var log = LoggerFactory.getLogger(this::class.java)


    /* unit tests */
    @BeforeEach
    fun setUp() {
        passwordEncoder = mock()
        users = mock()


        whenever(passwordEncoder.encode("timing-equaliser"))
            .thenReturn("dummy-hash")

        service = AuthenticationService(users, passwordEncoder)
    }

    @Test
    fun `should authenticate user with correct password`() {

        // Arrange
        val user = AuthUser(
            username = "john",
            passwordHash = "encoded-password"
        )

         /*when ever we requested particular feature return this*/
        whenever(users.findByUsername("john"))
            .thenReturn(Optional.of(user))

        whenever(
            passwordEncoder.matches(
                "password123",
                "encoded-password"
            )
        ).thenReturn(true)


        // Act
        val result = service.authenticate(
            "john",
            "password123",
        )

        // Assert
        assertNotNull(result) /*This checks whether result is NOT null.*/
        assertEquals("john", result.username)

        /*It checks whether your service actually called:*/
        verify(users).findByUsername("john")
        /*This checks whether your service called the password encoder's matches() method with the correct arguments.*/
        verify(passwordEncoder).matches(
            "password123",
            "encoded-password"
        )
    }

    @Test
    fun `should reject incorrect password`() {

        //Arrange
        val user = AuthUser(
            username = "john",
            passwordHash = "encoded-password"
        )

        whenever(users.findByUsername("john"))
            .thenReturn(Optional.of(user))

        whenever(passwordEncoder.matches("wrong-password", "encoded-password"))
            .thenReturn(false)

        // Act
        val result = service.authenticate(
            "john",
            "wrong-password"
        )

        //Assert
        assertNull(result)

        verify(passwordEncoder).matches(
            "wrong-password",
            "encoded-password"
        )
    }


    @Test
    fun `should reject unknown username and check dummy hash`() {

        //Arrange
        whenever(users.findByUsername("unknown"))
                .thenReturn(Optional.empty())

        /*Check before Each */
        whenever(passwordEncoder.matches("password123", "dummy-hash"))
            .thenReturn(false)


        // Act
        val result = service.authenticate(
            "unknown",
            "password123"
        )

        // Assert
        assertNull(result)

        verify(users).findByUsername("unknown")
        verify(passwordEncoder).matches(
            "password123",
            "dummy-hash"
        )

    }


    @Test
    fun `should encode password before creating account`() {

        // Arrange
        val user = AuthUser(
            username = "john",
            passwordHash = "bcrypt-hash"
        )

        whenever(users.findByUsername("john"))
            .thenReturn(Optional.empty())

        whenever(passwordEncoder.encode("password123"))
            .thenReturn("bcrypt-hash")

        /*any is a mockito-kotlin library function
        * This is Mockito's way of saying: Whenever someone calls users.save() with any AuthUser object, return the user object*/
        whenever(users.save(any<AuthUser>()))
            .thenReturn(user)

        // Act
        val result = service.createAccount(
            "john",
            "password123"
        )

        // Assert
        assertEquals("john", result?.username)
        assertEquals("bcrypt-hash", result?.passwordHash)

        verify(passwordEncoder).encode("password123")
        verify(users).save(any<AuthUser>())

    }

    /* end of unit tests */


}