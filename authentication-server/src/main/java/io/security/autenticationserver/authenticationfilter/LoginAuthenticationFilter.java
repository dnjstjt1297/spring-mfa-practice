package io.security.autenticationserver.authenticationfilter;

import io.security.autenticationserver.authentication.UsernamePasswordAuthentication;
import io.security.autenticationserver.authenticationfilter.util.CachedBodyHttpServletRequest;
import io.security.autenticationserver.authenticationfilter.util.JsonRequestBodyParser;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.*;
import java.util.Map;

@RequiredArgsConstructor
public class LoginAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        byte[] bodyBytes = JsonRequestBodyParser.extractRequestBody(request);
        Map<String, String> json = JsonRequestBodyParser.parseToMap(bodyBytes);

        if (json == null || !json.containsKey("username") || !json.containsKey("password")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String username = json.get("username");
        String password = json.get("password");

        Authentication authentication = new UsernamePasswordAuthentication(username, password);
        Authentication result = authenticationManager.authenticate(authentication);

        if (result.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(result);
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        CachedBodyHttpServletRequest rebuildRequest = new CachedBodyHttpServletRequest(request,bodyBytes);
        filterChain.doFilter(rebuildRequest, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals("/user/auth");
    }

}
