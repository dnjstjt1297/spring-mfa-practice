package io.security.businesslogicalserver.user;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class User {
    private String username;
    private String password;
    private String code;
}
