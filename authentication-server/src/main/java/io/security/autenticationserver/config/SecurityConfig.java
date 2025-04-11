package io.security.autenticationserver.config;

import io.security.autenticationserver.authenticationfilter.RefreshTokenAuthenticationFilter;
import io.security.autenticationserver.authenticationfilter.LoginAuthenticationFilter;
import io.security.autenticationserver.authenticationfilter.OtpAuthenticationFilter;
import io.security.autenticationserver.authenticationprovider.RefreshTokenAuthenticationProvider;
import io.security.autenticationserver.authenticationprovider.OtpAuthenticationProvider;
import io.security.autenticationserver.authenticationprovider.UsernamePasswordAuthenticationProvider;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    @Bean
    public AuthenticationManager authenticationManager( RefreshTokenAuthenticationProvider jwtAccessTokenAuthenticationProvider,
                                                        OtpAuthenticationProvider otpAuthenticationProvider,
                                                        UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider) {
        return new ProviderManager(List.of(
                jwtAccessTokenAuthenticationProvider,
                otpAuthenticationProvider,
                usernamePasswordAuthenticationProvider
        ));
    }

    @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new LoginAuthenticationFilter(authenticationManager);
    }

    @Bean
    public OtpAuthenticationFilter otpAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new OtpAuthenticationFilter(authenticationManager);
    }

    @Bean
    public RefreshTokenAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        return new RefreshTokenAuthenticationFilter(authenticationManager);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   LoginAuthenticationFilter loginAuthenticationFilter,
                                                   OtpAuthenticationFilter otpAuthenticationFilter,
                                                   RefreshTokenAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .addFilterBefore(loginAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(otpAuthenticationFilter, LoginAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll());

        return http.build();
    }
}