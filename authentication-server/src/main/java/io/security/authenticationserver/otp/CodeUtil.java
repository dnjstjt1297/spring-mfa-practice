package io.security.authenticationserver.otp;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CodeUtil {

    private CodeUtil() {}

    public static String generateCode() {
        String code;

        try{
            SecureRandom random = SecureRandom.getInstanceStrong(); // 랜덤 OTP 생성

            int c = random.nextInt(9000)+1000;
            code = String.valueOf(c);
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Failed to generate random code", e);
        }

        return code;
    }
}
