package io.security.businesslogicalserver.authenticationfilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.security.businesslogicalserver.authentication.UsernamePasswordAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

/**
 * JWT 기반 인증을 처리하는 필터 클래스.
 * 사용자가 요청에 JWT 토큰을 포함했을 경우 해당 토큰을 검증하고,
 * 사용자 정보를 SecurityContext에 등록하여 인증된 사용자로 설정함.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // application.properties에 설정된 서명 키 값을 주입받음 (Base64 인코딩된 문자열)
    @Value("${jwt.signing.key}")
    private String signingKey;

    /**
     * 요청이 들어올 때 마다 실행되며 JWT를 검사하고 SecurityContext에 인증 정보를 등록함.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청 헤더에서 JWT를 가져옴
        String jwt = request.getHeader("Authorization");

        // 서명 키를 디코딩하여 SecretKey 객체로 변환
        SecretKey key = Keys.hmacShaKeyFor(
                Base64.getDecoder().decode(signingKey)
        );

        // JWT를 파싱하고 서명을 검증
        Jws<Claims> jws = Jwts
                .parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt);

        // payload에서 claims 추출 (subject는 사용자명 등)
        Claims claims = jws.getPayload();
        String username = String.valueOf(claims.getSubject());

        // 사용자 권한 부여 (여기서는 간단히 "user" 권한 하나만 부여)
        GrantedAuthority a = new SimpleGrantedAuthority("user");

        // UsernamePasswordAuthentication 객체를 만들어 SecurityContext에 등록
        var auth = new UsernamePasswordAuthentication(username,null, List.of(a));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // 다음 필터 체인으로 요청을 넘김
        filterChain.doFilter(request, response);
    }


    /**
     * /login만 필터(JwtAuthenticationFilter)를 적용 하지 않는다.
     **/
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath()
                .equals("/login");
    }
}
