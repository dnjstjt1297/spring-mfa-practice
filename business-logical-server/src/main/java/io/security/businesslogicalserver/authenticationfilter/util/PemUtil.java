package io.security.businesslogicalserver.authenticationfilter.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class PemUtil {

    public static PublicKey loadPublicKey(String filePath) {
        try {
            InputStream inputStream = PemUtil.class.getClassLoader().getResourceAsStream(filePath);
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
}
