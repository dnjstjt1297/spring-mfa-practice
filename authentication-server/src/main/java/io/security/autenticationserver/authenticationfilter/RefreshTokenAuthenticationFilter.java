package io.security.autenticationserver.authenticationfilter;

import io.security.autenticationserver.authentication.RefreshTokenAuthentication;
import io.security.autenticationserver.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Access 토큰의 유효성을 검사하는 필터
 * "/user/access_token" 요청에서 Authorization 헤더에 담긴 JWT 토큰을 검증,
 * 검증단계에서는 토큰 만료기간이 현재 시간 이후일 때(access token 발급 조건)를 검증
 * 유저 정보를 인증 객체로 만들어 인증을 진행함.
 */
public class RefreshTokenAuthenticationFilter extends OncePerRequestFilter {

    // 인증을 처리할 AuthenticationManager 주입
    private final AuthenticationManager authenticationManager;

    public RefreshTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String refreshToken = CookieUtil.extractRefreshTokenFromCookies(request);
        if (refreshToken != null) {
            Authentication authentication = new RefreshTokenAuthentication(refreshToken);
            try {
                authenticationManager.authenticate(authentication);

                // 인증 성공: 다음 필터로 진행
                filterChain.doFilter(request, response);
            } catch (AuthenticationException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Refresh Token");
            }
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("/user/refresh_token".equals(request.getRequestURI()) && request.getMethod().equals("POST"));
    }
}
