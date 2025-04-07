package io.security.businesslogicalserver.config;

import io.security.businesslogicalserver.authenticationfilter.InitialAuthenticationFilter;
import io.security.businesslogicalserver.authenticationfilter.JwtAuthenticationFilter;
import io.security.businesslogicalserver.authenticationprovider.OtpAuthenticationProvider;
import io.security.businesslogicalserver.authenticationprovider.UsernamePasswordAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public InitialAuthenticationFilter initialAuthenticationFilter() {
       return new InitialAuthenticationFilter(authenticationManager());
    }



    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    private final OtpAuthenticationProvider otpAuthenticationProvider;

    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                List.of(
                        otpAuthenticationProvider,
                        usernamePasswordAuthenticationProvider
                )
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterAt(initialAuthenticationFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter(), BasicAuthenticationFilter.class);

        http.
                authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated());

        return http.build();
    }
}
