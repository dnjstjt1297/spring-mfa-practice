package io.security.autenticationserver.authenticationprovider;

import io.security.autenticationserver.authentication.OtpAuthentication;
import io.security.autenticationserver.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

@RequiredArgsConstructor
public class OtpAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String code = String.valueOf(authentication.getCredentials());

        if (userService.isValidOtp(username, code)) {
            return new OtpAuthentication(
                    username,
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_USER"))
            );
        }

        throw new BadCredentialsException("Invalid OTP code");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
