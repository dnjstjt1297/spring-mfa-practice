package io.security.businesslogicalserver.authenticationprovider;


import io.security.businesslogicalserver.authentication.UsernamePasswordAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        if (authorities.isEmpty()) {
            throw new BadCredentialsException("No roles assigned");
        }

        boolean hasUserRole = authorities.stream()
                .anyMatch(auth -> "ROLE_USER".equals(auth.getAuthority()));

        if (!hasUserRole) {
            throw new BadCredentialsException("Required role ROLE_USER not found");
        }

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
