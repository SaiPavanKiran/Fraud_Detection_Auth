package org.rspk.fraud_detection.auth.model

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.hibernate.Hibernate
import org.hibernate.annotations.CreationTimestamp
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "users")
data class AuthUser(
    val username:String,
    val passwordHash:String,
    @CreationTimestamp
    val creationAt: Instant? = null,
) {

    constructor() : this("","") {}
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: UUID? = null
        private set


    fun setId(id: UUID) {
        this.id = id
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || Hibernate.getClass(this) != Hibernate.getClass(other)) return false
        other as AuthUser
        return id != null && id == other.id
    }

    override fun hashCode(): Int = Hibernate.getClass(this).hashCode()

}
