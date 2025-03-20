package com.plate.hy.domain

import jakarta.persistence.*
import lombok.AccessLevel
import lombok.Getter
import lombok.NoArgsConstructor
import org.springframework.security.crypto.password.PasswordEncoder

@Entity
@Table(name = "members")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
class Member private constructor(
    @Column(name = "member_name", nullable = false)
    private val name: String,

    @Column(name = "member_password", nullable = false)
    private val password: String
) {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", nullable = false)
    private val id: Long? = null

    companion object {
        fun create(name: String, password: String?, passwordEncoder: PasswordEncoder): Member {
            return Member(name, passwordEncoder.encode(password))
        }
    }
}
