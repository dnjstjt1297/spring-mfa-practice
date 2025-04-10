package io.security.businesslogicalserver.config;

import io.security.businesslogicalserver.authenticationfilter.JwtAuthenticationFilter;
import io.security.businesslogicalserver.authenticationprovider.JwtAuthenticationProvider;
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
public class SecurityConfig {

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(
                jwtAuthenticationProvider()
        ));
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(authenticationManager());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(jwtAuthenticationFilter(), BasicAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest()
                        .authenticated());
        return http.build();
    }
}
