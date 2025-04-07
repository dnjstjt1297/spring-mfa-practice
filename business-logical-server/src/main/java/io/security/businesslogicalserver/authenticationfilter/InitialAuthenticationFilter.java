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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;


@RequiredArgsConstructor
public class InitialAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager manager;

    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String code = request.getHeader("code");

        if(code == null){
            Authentication auth = new UsernamePasswordAuthentication(username, password);
            manager.authenticate(auth);
        }
        else {
            Authentication auth = new OtpAuthentication(username, code);
            manager.authenticate(auth);
            System.out.println(signingKey);
            SecretKey key = Keys.hmacShaKeyFor(
                    Base64.getDecoder().decode(signingKey)
            );

            String jwt = Jwts.builder()
                    .claims(Map.of("username", username))
                    .signWith(key)
                    .compact();

            response.setHeader("Authorization",jwt);
        }

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().contains("/login");
    }
}
