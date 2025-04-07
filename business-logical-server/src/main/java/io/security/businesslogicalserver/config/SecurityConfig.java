package io.security.businesslogicalserver.config;

import io.security.businesslogicalserver.authenticationfilter.InitialAuthenticationFilter;
import io.security.businesslogicalserver.authenticationfilter.JwtAuthenticationFilter;
import io.security.businesslogicalserver.authenticationprovider.OtpAuthenticationProvider;
import io.security.businesslogicalserver.authenticationprovider.UsernamePasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // 초기 인증 필터 (사용자명/비밀번호를 처리)
    @Bean
    public InitialAuthenticationFilter initialAuthenticationFilter() {
        return new InitialAuthenticationFilter(authenticationManager());
    }

    // JWT 인증 필터 (JWT를 통한 후속 요청 인증)
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    // OTP 인증 제공자 (사용자에게 전달된 OTP를 검증)
    private final OtpAuthenticationProvider otpAuthenticationProvider;

    // 사용자명/비밀번호 인증 제공자
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    // AuthenticationManager는 등록된 여러 AuthenticationProvider를 통해 인증을 수행
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                List.of(
                        otpAuthenticationProvider,
                        usernamePasswordAuthenticationProvider
                )
        );
    }

    // SecurityFilterChain 정의: 필터 순서 및 인증 정책 설정
    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        http
                // CSRF 보안 비활성화 (REST API 서버의 경우 보통 비활성화)
                .csrf(AbstractHttpConfigurer::disable)
                // 초기 인증 필터를 BasicAuthenticationFilter 위치에 등록
                .addFilterAt(initialAuthenticationFilter(), BasicAuthenticationFilter.class)
                // JWT 인증 필터를 BasicAuthenticationFilter 다음에 등록
                .addFilterAfter(jwtAuthenticationFilter(), BasicAuthenticationFilter.class);

        // 모든 요청은 인증을 요구
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated());

        return http.build();
    }
}
