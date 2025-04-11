package io.security.autenticationserver.user.controller;

import io.security.autenticationserver.user.dto.TokenResponse;
import io.security.autenticationserver.user.entity.Otp;
import io.security.autenticationserver.user.entity.User;
import io.security.autenticationserver.user.service.UserService;
import io.security.autenticationserver.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/user/add")
    public void addUser(@RequestBody User user) {
        userService.addUser(user);
    }

    @PostMapping("/user/auth")
    public void auth(@RequestBody User user) {
        userService.auth(user);
    }

    @PostMapping("/user/otp_check")
    public ResponseEntity<?> otpCheck(@RequestBody Otp otp, HttpServletResponse response) throws Exception {
        // 1. 토큰 생성
        String accessToken = userService.generateJwtToken(otp.getUsername());
        String refreshToken = userService.generateRefreshToken(otp.getUsername());

        // 2. Refresh Token → HttpOnly 쿠키에 저장
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true) // HTTPS 환경일 경우 true
                .path("/")
                .maxAge(Duration.ofDays(7)) // 7일 유지
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // 3. Access Token 응답
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }

    @PostMapping("/user/refresh_token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // 1. 쿠키에서 refreshToken 추출
        String refreshToken = CookieUtil.extractRefreshTokenFromCookies(request);
        if (refreshToken == null) {
            return ResponseEntity.status(HttpServletResponse.SC_FORBIDDEN)
                    .body("Refresh token not found");
        }

        // 2. 서비스로 전달해 새 토큰 생성
        TokenResponse tokenResponse = userService.responseRefreshToken(refreshToken);

        // 3. 새 refreshToken 쿠키로 내려주기
        ResponseCookie cookie = ResponseCookie.from("refreshToken", tokenResponse.getRefreshToken())
                .httpOnly(true)
                .secure(true) // HTTPS 환경에서만 사용 시 true
                .path("/")
                .maxAge(7 * 24 * 60 * 60) // 7일
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // 4. accessToken은 JSON 바디로 응답
        return ResponseEntity.ok(Map.of("accessToken", tokenResponse.getAccessToken()));
    }

}





