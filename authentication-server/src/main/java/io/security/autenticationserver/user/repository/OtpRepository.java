package io.security.autenticationserver.user.repository;

import io.security.autenticationserver.user.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, String> {
    Optional<Otp> findOtpByUsername(String username);
}
