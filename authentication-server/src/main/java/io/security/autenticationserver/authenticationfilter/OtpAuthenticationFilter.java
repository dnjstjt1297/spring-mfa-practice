package io.security.autenticationserver.authenticationfilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.security.autenticationserver.authentication.OtpAuthentication;
import io.security.autenticationserver.authenticationfilter.util.CachedBodyHttpServletRequest;
import io.security.autenticationserver.authenticationfilter.util.JsonRequestBodyParser;
import io.security.autenticationserver.authenticationfilter.util.PemUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Map;

@RequiredArgsConstructor
public class OtpAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        byte[] bodyBytes = JsonRequestBodyParser.extractRequestBody(request);
        Map<String, String> json = JsonRequestBodyParser.parseToMap(bodyBytes);

        if (json == null || !json.containsKey("username") || !json.containsKey("code")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String username = json.get("username");
        String code = json.get("code");

        Authentication authentication = new OtpAuthentication(username, code);
        Authentication result = authenticationManager.authenticate(authentication);

        if (result.isAuthenticated()) {
            try {
                String jwt = generateJwtToken(username, result);

                response.setHeader("Authorization", jwt);

                CachedBodyHttpServletRequest rebuildRequest = new CachedBodyHttpServletRequest(request, bodyBytes);
                filterChain.doFilter(rebuildRequest, response);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/user/otpCheck".equals(request.getRequestURI());
    }

    private String generateJwtToken(String username, Authentication result) throws Exception {
        PrivateKey privateKey = PemUtil.loadPrivateKey("keys/private.pem");
        return Jwts.builder()
                .claim("username", username)
                .claim("roles", result.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .signWith(privateKey)
                .compact();
    }

}
