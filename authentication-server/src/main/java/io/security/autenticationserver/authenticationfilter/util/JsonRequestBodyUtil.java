package io.security.autenticationserver.authenticationfilter.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class JsonRequestBodyUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static byte[] extractRequestBody(HttpServletRequest request) throws IOException {
        return request.getInputStream().readAllBytes();
    }

    public static Map<String, String> parseToMap(byte[] bodyBytes) {
        try {
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            return objectMapper.readValue(body, new TypeReference<>() {});
        } catch (IOException e) {
            return null;
        }
    }

    public static <T> T parseToObject(byte[] bodyBytes, Class<T> clazz) {
        try {
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            return objectMapper.readValue(body, clazz);
        } catch (IOException e) {
            return null;
        }
    }
}
