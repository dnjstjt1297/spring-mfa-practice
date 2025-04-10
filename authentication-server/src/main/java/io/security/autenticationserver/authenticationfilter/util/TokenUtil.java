package io.security.autenticationserver.authenticationfilter.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.stream.Collectors;

public class TokenUtil {

    public static PrivateKey loadPrivateKey(String filePath) throws Exception{
        InputStream inputStream = TokenUtil.class.getClassLoader().getResourceAsStream(filePath);
        String pem = new BufferedReader(new InputStreamReader(Objects.requireNonNull(inputStream)))
                .lines()
                .filter(line -> !line.startsWith("-----"))
                .collect(Collectors.joining());

        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static PublicKey loadPublicKey(String filePath) {
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

    public static Claims getClaim(String token) {
        PublicKey publicKey = TokenUtil.loadPublicKey("keys/public.pem");
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims;
    }

    public static String generateJwtToken(String username) throws Exception {
        PrivateKey privateKey = TokenUtil.loadPrivateKey("keys/private.pem");
        String accessToken = Jwts.builder()
                .claim("username", username)
                .expiration(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES)))
                .signWith(privateKey)
                .compact();

        return accessToken;
    }

}
