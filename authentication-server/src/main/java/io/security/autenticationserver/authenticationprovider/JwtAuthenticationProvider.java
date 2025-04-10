package io.security.autenticationserver.authenticationprovider;

import io.security.autenticationserver.authentication.JwtAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Date;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof JwtAuthentication jwtAuth)) {
            throw new BadCredentialsException("Invalid authentication type");
        }

        Date expiry = jwtAuth.getExpiration();
        if(expiry.before(new Date())){
            throw new BadCredentialsException("Invalid authentication expiration");
        }

        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}
