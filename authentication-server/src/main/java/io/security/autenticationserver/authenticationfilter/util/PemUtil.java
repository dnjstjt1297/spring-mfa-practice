package io.security.autenticationserver.authenticationfilter.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.Collectors;

public class PemUtil {

    public static PrivateKey loadPrivateKey(String filePath) throws Exception{
        InputStream inputStream = PemUtil.class.getClassLoader().getResourceAsStream(filePath);
        String pem = new BufferedReader(new InputStreamReader(Objects.requireNonNull(inputStream)))
                .lines()
                .filter(line -> !line.startsWith("-----"))
                .collect(Collectors.joining());

        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

}
