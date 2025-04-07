package io.security.businesslogicalserver.authenticationprovider;

import io.security.businesslogicalserver.authentication.AuthenticationProxy;
import io.security.businesslogicalserver.authentication.OtpAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * OTP(One-Time Password) 인증을 처리하는 커스텀 AuthenticationProvider.
 * 사용자가 OTP를 입력하면, 해당 값을 인증 서버로 전송하여 유효성을 확인하고 인증 처리를 수행함.
 */
@Component
@RequiredArgsConstructor
public class OtpAuthenticationProvider implements AuthenticationProvider {

    // 인증 서버와 통신하여 OTP 유효성을 검증하는 역할을 담당
    private final AuthenticationProxy proxy;

    /**
     * 실제 인증 로직을 수행하는 메서드.
     * OTP를 기반으로 인증을 수행하며, 인증에 성공하면 OtpAuthentication 객체를 반환함.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 입력받은 사용자 이름
        String username = authentication.getName();
        // 입력받은 OTP 코드
        String code = String.valueOf(authentication.getCredentials());

        // AuthenticationProxy를 통해 외부 인증 서버에 OTP 검증 요청
        boolean result = proxy.sendOtp(username, code);

        if (result) {
            // 인증 성공 시, 인증된 OtpAuthentication 객체 반환
            return new OtpAuthentication(username, code);
        } else {
            // 인증 실패 시 예외 발생
            throw new BadCredentialsException("Bad Credentials.");
        }
    }

    /**
     * 이 Provider가 처리할 수 있는 Authentication 객체 타입을 지정.
     * 여기서는 OtpAuthentication 타입만 처리 가능함.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OtpAuthentication.class.isAssignableFrom(authentication);
    }
}
