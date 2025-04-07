package io.security.businesslogicalserver.authentication;

import io.security.businesslogicalserver.user.User;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * 인증 서버와의 통신을 담당하는 프록시 클래스.
 * 사용자 인증 및 OTP 인증을 외부 인증 서버로 위임하여 처리함.
 */
@Component
@RequiredArgsConstructor
public class AuthenticationProxy {

    // Spring의 HTTP 요청 도구
    private final RestTemplate rest;

    // 인증 서버의 기본 URL (application.properties 또는 yml에서 주입)
    @Value("${auth.server.base.url}")
    public String baseUrl;

    /**
     * 사용자 이름과 비밀번호를 이용해 인증 요청을 전송.
     * 성공 여부와 관계없이 예외를 던지지 않으면 무조건 성공한 것처럼 보일 수 있음.
     *
     * @param username 사용자 이름
     * @param password 사용자 비밀번호
     */
    public void sendAuth(String username, String password) {
        String url = baseUrl + "/user/auth";  // 인증 서버의 인증 엔드포인트

        // 인증에 필요한 사용자 정보 설정
        var body = new User();
        body.setUsername(username);
        body.setPassword(password);

        // 요청 본문 생성
        var request = new HttpEntity<>(body);

        // POST 방식으로 인증 요청 전송
        rest.postForEntity(url, request, Void.class);
    }

    /**
     * OTP 코드 검증 요청을 전송하여 성공 여부를 반환.
     *
     * @param username 사용자 이름
     * @param code     OTP 코드
     * @return OTP 인증 성공 여부
     */
    public boolean sendOtp(String username, String code) {
        String url = baseUrl + "/otp/check";  // OTP 검증 엔드포인트

        var body = new User();
        body.setUsername(username);
        body.setCode(code);

        var request = new HttpEntity<>(body);

        // POST 요청 보내고 응답 상태 코드로 인증 성공 여부 판단
        var response = rest.postForEntity(url, request, Void.class);

        return response.getStatusCode().equals(HttpStatus.OK);
    }
}
