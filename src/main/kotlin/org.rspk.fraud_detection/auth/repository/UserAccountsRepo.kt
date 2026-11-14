package org.rspk.fraud_detection.auth.repository

import org.rspk.fraud_detection.auth.model.AuthUser
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional
import java.util.UUID

@Repository
interface UserAccountsRepo : JpaRepository<AuthUser, UUID> {
    fun findByUsername(username:String) : Optional<AuthUser>
}