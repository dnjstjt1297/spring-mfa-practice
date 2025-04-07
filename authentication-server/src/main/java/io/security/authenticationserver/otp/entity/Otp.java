package io.security.authenticationserver.otp.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class Otp {

    @Id
    private String username;
    private String code;

}
