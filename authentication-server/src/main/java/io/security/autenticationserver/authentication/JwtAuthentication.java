package io.security.autenticationserver.authentication;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Date;
import java.util.List;

@Getter
public class JwtAuthentication implements Authentication {

    private final String username;
    private final List<SimpleGrantedAuthority> authorities;
    private final Date expiration;
    private boolean authenticated = true;

    public JwtAuthentication(String username, List<SimpleGrantedAuthority> authorities, Date expiration) {
        this.username = username;
        this.authorities = authorities;
        this.expiration = expiration;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public Object getCredentials() {
        return null; // JWT 기반 인증이라면 보통 null 처리
    }

    @Override
    public Object getDetails() {
        return null; // 필요하면 추가 (IP, 세션 등)
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
        this.authenticated = authenticated;
    }

    @Override
    public String getName() {
        return username;
    }
}
