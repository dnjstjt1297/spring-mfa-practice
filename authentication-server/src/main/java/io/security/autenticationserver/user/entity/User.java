package io.security.autenticationserver.user.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter @Setter
public class User {

    @Id
    private String username;

    private String password;

}
