package io.security.autenticationserver.authenticationfilter;

import io.security.autenticationserver.authentication.OtpAuthentication;
import io.security.autenticationserver.util.JsonRequestBodyUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * OTP 인증 필터
 * 사용자가 "/user/otp_check" 경로로 로그인 요청을 할 때
 * JSON 형식의 사용자 이름과 OTP코드를 받아 인증 처리하는 필터.
 */
public class OtpAuthenticationFilter extends OncePerRequestFilter {

    // 인증을 처리할 AuthenticationManager 의존석 주입
    private final AuthenticationManager authenticationManager;

    public OtpAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 요청 부분을 바이트 배열로 추출
        byte[] bodyBytes = JsonRequestBodyUtil.extractRequestBody(request);

        // Json 문자열을 Map으로 파싱
        Map<String, String> json = JsonRequestBodyUtil.parseToMap(bodyBytes);

        // username 또는 code 없으면 400(Bad Request) 응답
        if (json == null || !json.containsKey("username") || !json.containsKey("code")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 사용자 이름과 코드 추출
        String username = json.get("username");
        String code = json.get("code");


        // OTP 인증 토큰 생성
        Authentication authentication = new OtpAuthentication(username, code);
        // AuthenticationManager를 통해 인증 처리
        authenticationManager.authenticate(authentication);

        // 바디를 복구한 요청 객체 생성 후 다음 필터로 전달
        CachedBodyHttpServletRequest rebuildRequest = new CachedBodyHttpServletRequest(request, bodyBytes);
        filterChain.doFilter(rebuildRequest, response);
    }

    /**
     * "/user/otp_check" 경로가 아닌 요청에는 필터 적용 안 함
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        return !"/user/otp_check".equals(request.getRequestURI());
    }

}
