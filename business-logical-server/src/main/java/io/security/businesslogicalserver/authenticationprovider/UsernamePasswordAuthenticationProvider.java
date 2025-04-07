package io.security.businesslogicalserver.authenticationprovider;

import io.security.businesslogicalserver.authentication.AuthenticationProxy;
import io.security.businesslogicalserver.authentication.UsernamePasswordAuthentication;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * 사용자 이름과 비밀번호 기반 인증을 처리하는 AuthenticationProvider.
 * 사용자가 로그인 시 입력한 username/password를 외부 인증 서버에 전달하여 인증을 수행함.
 */
@Component
@RequiredArgsConstructor
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    // 외부 인증 서버와 통신하기 위한 중개 클래스 (AuthenticationProxy)
    private final AuthenticationProxy proxy;

    /**
     * 실제 인증 로직 수행.
     * 사용자 이름과 비밀번호를 기반으로 인증을 시도하며, 인증 성공 시 Authentication 객체 반환.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 입력된 사용자 이름 가져오기
        String username = authentication.getName();
        // 입력된 비밀번호 가져오기
        String password = String.valueOf(authentication.getCredentials());

        // 인증 서버에 사용자 정보 전송 (인증 실패 시 예외 발생 예상)
        proxy.sendAuth(username, password);

        // 인증 성공 시, 인증된 UsernamePasswordAuthentication 객체 반환
        return new UsernamePasswordAuthentication(username, password);
    }

    /**
     * 이 Provider가 처리할 수 있는 Authentication 객체 유형을 지정.
     * 여기서는 UsernamePasswordAuthentication 타입만 처리함.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
    }
}
