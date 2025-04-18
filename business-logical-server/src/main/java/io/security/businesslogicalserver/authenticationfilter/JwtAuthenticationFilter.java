package io.security.businesslogicalserver.authenticationfilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.security.businesslogicalserver.authentication.UsernamePasswordAuthentication;
import io.security.businesslogicalserver.authenticationfilter.util.TokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public Claims getClaim(String token) {
        PublicKey publicKey = TokenUtil.loadPublicKey("keys/public.pem");
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");

        Claims claims = getClaim(token);
        String username = claims.get("username", String.class);
        List<String> roles = claims.get("roles", List.class);
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new).toList();

        Authentication authentication = new UsernamePasswordAuthentication(username, null, authorities);
        authenticationManager.authenticate(authentication);

        SecurityContextHolder.getContext().setAuthentication(authentication);

    }

}
