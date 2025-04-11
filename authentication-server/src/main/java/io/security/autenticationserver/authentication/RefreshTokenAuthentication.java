package io.security.autenticationserver.authentication;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.List;

@Getter
public class RefreshTokenAuthentication implements Authentication {

    private final String token;
    private String username; // 인증 후 설정됨
    private boolean authenticated;

    // 인증 전: 토큰만 있는 상태
    public RefreshTokenAuthentication(String token) {
        this.token = token;
        this.authenticated = false;
    }

    // 인증 후: username 포함, 인증 완료 상태
    public RefreshTokenAuthentication(String token, String username, boolean authenticated) {
        this.token = token;
        this.username = username;
        this.authenticated = authenticated;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(); // 필요 시 권한 추가
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return null;
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
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return username != null ? username : "";
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}
