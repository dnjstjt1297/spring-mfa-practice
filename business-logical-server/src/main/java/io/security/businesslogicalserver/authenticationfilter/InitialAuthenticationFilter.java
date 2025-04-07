package io.security.businesslogicalserver.authenticationfilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.security.businesslogicalserver.authentication.OtpAuthentication;
import io.security.businesslogicalserver.authentication.UsernamePasswordAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;


/**
 * 로그인 시 실행되는 커스텀 필터
 * - ID/PW 인증 or OTP 인증 처리
 * - OTP 인증 성공 시 JWT 생성 및 반환
 */
@RequiredArgsConstructor
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    // 스프링 시큐리티의 인증 매니저
    private final AuthenticationManager manager;

    // application.properties 또는 application.yml에서 주입받는 JWT 서명 키
    @Value("${jwt.signing.key}")
    private String signingKey;

    /**
     * 필터의 핵심 로직
     * - 헤더에서 username, password, code를 추출
     * - code가 없으면 ID/PW 인증을 수행
     * - code가 존재하면 OTP 인증을 수행한 뒤 JWT 발급
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 요청 헤더에서 필요한 값 추출
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        if(code == null){ // 1단계: ID/PW 로그인 처리
            Authentication auth = new UsernamePasswordAuthentication(username, password);
            manager.authenticate(auth);
        }
        else {  // 2단계: OTP 인증 및 JWT 생성
            Authentication auth = new OtpAuthentication(username, code);
            manager.authenticate(auth);

            // 서명 키를 Base64로 디코딩해서 SecretKey 생성
            SecretKey key = Keys.hmacShaKeyFor(
                    Base64.getDecoder().decode(signingKey)
            );

            // JWT 생성 (username claim 포함, refresh 토큰, 만료 시간 등 구현x)
            String jwt = Jwts.builder()
                    .claims(Map.of("username", username))
                    .signWith(key)
                    .compact();

            // JWT를 응답 헤더에 담아 클라이언트에게 반환
            response.setHeader("Authorization",jwt);
        }
    }

    /**
     * login일 때만 필터(initialAuthenticationFilter)를 적용 한다.
     **/
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().contains("/login");
    }
}
