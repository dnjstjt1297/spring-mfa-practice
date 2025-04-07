package io.security.authenticationserver.otp;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.NoSuchElementException;

public class GeneratedCodeUtil {

    private GeneratedCodeUtil() {}

    public static String generateCode() {
        String code;

        try{
            SecureRandom random = SecureRandom.getInstanceStrong();

            int c = random.nextInt(9000)+1000;
            code = String.valueOf(c);
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Failed to generate random code", e);
        }

        return code;
    }
}
