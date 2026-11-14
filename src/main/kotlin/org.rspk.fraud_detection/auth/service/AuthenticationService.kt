package org.rspk.fraud_detection.auth.service

import org.rspk.fraud_detection.auth.repository.UserAccountsRepo
import org.rspk.fraud_detection.auth.model.AuthUser
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import kotlin.jvm.optionals.getOrNull

@Service
class AuthenticationService(
    private val users: UserAccountsRepo,
    private val passwordEncoder: PasswordEncoder,
) {
    // Verified against when the user does not exist, so "unknown user" and "wrong password" take the same time.
    private val dummyHash: String = requireNotNull(passwordEncoder.encode("timing-equaliser"))

    /** Returns the user if the credentials are valid, otherwise null. Callers must not reveal which part was wrong. */
    @Transactional(readOnly = true)
    fun authenticate(username: String, password: String): AuthUser? {
        val user = users.findByUsername(username).orElse(null)
        val hashToCheck = user?.passwordHash ?: dummyHash
        val matches = passwordEncoder.matches(password, hashToCheck)
        return if (user != null && matches) user else null
    }


    @Transactional
    fun createAccount(
        username:String,
        password:String
    ): AuthUser? {
        return if(users.findByUsername(username).getOrNull() == null) {
            users.save(AuthUser(username,passwordEncoder.encode(password) ?: throw BadCredentialsException("unable to hash the password")))
        } else null
    }
}