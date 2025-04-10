package io.security.autenticationserver.user.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password; // OTP 인증 시에는 null 가능
    private String code;     // 로그인 시에는 null 가능
}
