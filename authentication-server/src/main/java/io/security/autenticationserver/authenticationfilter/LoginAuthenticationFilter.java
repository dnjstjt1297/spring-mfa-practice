package io.security.autenticationserver.authenticationfilter;

import io.security.autenticationserver.authentication.UsernamePasswordAuthentication;
import io.security.autenticationserver.authenticationfilter.util.CachedBodyHttpServletRequest;
import io.security.autenticationserver.authenticationfilter.util.JsonRequestBodyUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.*;
import java.util.Map;

/**
 * 비밀번호 인증 필터
 * 사용자가 "/user/auth" 경로로 로그인 요청을 할 때
 * JSON 형식의 사용자 이름과 비밀번호를 받아 인증 처리하는 필터입니다.
 */
@RequiredArgsConstructor
public class LoginAuthenticationFilter extends OncePerRequestFilter {

    // 인증을 처리할 AuthenticationManager 의존석 주입
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 요청 부분을 바이트 배열로 추출
        byte[] bodyBytes = JsonRequestBodyUtil.extractRequestBody(request);

        // Json 문자열을 Map으로 파싱
        Map<String, String> json = JsonRequestBodyUtil.parseToMap(bodyBytes);

        // username 또는 password가 없으면 400(Bad Request) 응답
        if (json == null || !json.containsKey("username") || !json.containsKey("password")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 사용자 이름과 비밀번호 추출
        String username = json.get("username");
        String password = json.get("password");

        // 사용자 인증 토큰 생성
        Authentication authentication = new UsernamePasswordAuthentication(username, password);
        // AuthenticationManager를 통해 인증 처리
        Authentication result = authenticationManager.authenticate(authentication);
        // 인증이 되면 결과 저장
        SecurityContextHolder.getContext().setAuthentication(result);

        // 한번 읽은 입력 스트림을 다시 사용할 수 있도록 요청 래핑
        CachedBodyHttpServletRequest rebuildRequest = new CachedBodyHttpServletRequest(request,bodyBytes);

        // 다음 필터로 요청 전달
        filterChain.doFilter(rebuildRequest, response);
    }

    /**
     * "/user/auth" 경로가 아닌 경우에는 이 필터를 적용하지 않는다.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals("/user/auth");
    }

}
