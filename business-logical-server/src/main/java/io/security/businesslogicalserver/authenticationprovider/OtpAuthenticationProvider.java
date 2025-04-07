package io.security.businesslogicalserver.authenticationprovider;

import io.security.businesslogicalserver.authentication.AuthenticationProxy;
import io.security.businesslogicalserver.authentication.OtpAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OtpAuthenticationProvider implements AuthenticationProvider {
    private final AuthenticationProxy proxy;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String code = String.valueOf(authentication.getCredentials());

        boolean result = proxy.sendOtp(username, code);

        if (result) {
            return new OtpAuthentication(username, code);
        }
        else {
            throw new BadCredentialsException("Bad Credentials.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
