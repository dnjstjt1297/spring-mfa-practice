package io.security.autenticationserver.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.security.autenticationserver.user.entity.RefreshToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

public class TokenUtil {

    public static RefreshToken generateUuidToken(String username){
        String uuid = UUID.randomUUID().toString();
        LocalDateTime localDateTime = LocalDateTime.now().plusDays(7);
        return new RefreshToken(username,uuid,localDateTime);
    }

    public static String generateJwtToken(String username, List<SimpleGrantedAuthority> roles) throws Exception {
        PrivateKey privateKey = loadPrivateKey("keys/private.pem");
        String accessToken = Jwts.builder()
                .claim("username", username)
                .claim("roles", roles)
                .expiration(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES)))
                .signWith(privateKey)
                .compact();

        return accessToken;
    }



    public static Claims getClaim(String token) {
        PublicKey publicKey = TokenUtil.loadPublicKey("keys/public.pem");
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static PrivateKey loadPrivateKey(String filePath) throws Exception{
        InputStream inputStream = TokenUtil.class.getClassLoader().getResourceAsStream(filePath);
        String pem = new BufferedReader(new InputStreamReader(Objects.requireNonNull(inputStream)))
                .lines()
                .filter(line -> !line.startsWith("-----"))
                .collect(Collectors.joining());

        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static PublicKey loadPublicKey(String filePath) {
        try {
            InputStream inputStream = TokenUtil.class.getClassLoader().getResourceAsStream(filePath);
            if (inputStream == null) {
                throw new IllegalArgumentException("Public key file not found: " + filePath);
            }

            String pem = new BufferedReader(new InputStreamReader(inputStream))
                    .lines()
                    .filter(line -> !line.startsWith("-----"))
                    .collect(Collectors.joining());

            byte[] keyBytes = Base64.getDecoder().decode(pem);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key from: " + filePath, e);
        }
    }

    public static String extractUsername(String token) {

        try {
            String payload = new String(
                    Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                    StandardCharsets.UTF_8
            );

            return new ObjectMapper()
                    .readTree(payload)
                    .path("username")
                    .asText();
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT structure or missing username", e);
        }
    }


}
