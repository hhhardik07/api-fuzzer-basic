
package com.apifuzzer.security;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResponseSanitizerTest {

    private final ResponseSanitizer sanitizer =
            new ResponseSanitizer();

    @Test
    void shouldRedactSensitiveHeaders() {
        Map<String, List<String>> headers = Map.of(
                "Authorization", List.of("Bearer secret-token"),
                "Cookie", List.of("SESSION=secret-session"),
                "Content-Type", List.of("application/json")
        );

        Map<String, List<String>> result =
                sanitizer.sanitizeHeaders(headers);

        assertEquals(
                "[REDACTED]",
                result.get("Authorization").get(0)
        );

        assertEquals(
                "[REDACTED]",
                result.get("Cookie").get(0)
        );

        assertEquals(
                "application/json",
                result.get("Content-Type").get(0)
        );
    }

    @Test
    void shouldRedactSensitiveJsonValues() {
        String body = """
                {
                    "username": "student",
                    "password": "secret123",
                    "access_token": "abc123"
                }
                """;

        String result = sanitizer.sanitizeBody(body);

        assertTrue(result.contains("\"username\":\"student\""));
        assertFalse(result.contains("secret123"));
        assertFalse(result.contains("abc123"));
        assertTrue(result.contains("[REDACTED]"));
    }

    @Test
    void shouldRedactBearerTokensInText() {
        String input = "Authorization: Bearer abc.def.ghi";

        String result = sanitizer.sanitizeText(input);

        assertFalse(result.contains("abc.def.ghi"));
        assertTrue(result.contains("Bearer [REDACTED]"));
    }

    @Test
    void shouldRedactBasicCredentialsInText() {
        String input =
                "Authorization: Basic dXNlcjpwYXNzd29yZA==";

        String result = sanitizer.sanitizeText(input);

        assertFalse(result.contains("dXNlcjpwYXNzd29yZA=="));
        assertTrue(result.contains("Basic [REDACTED]"));
    }

    @Test
    void shouldPreserveOrdinaryResponseContent() {
        String body =
                "{\"username\":\"student\",\"status\":\"active\"}";

        String result = sanitizer.sanitizeBody(body);

        assertTrue(result.contains("student"));
        assertTrue(result.contains("active"));
    }

    @Test
    void shouldHandleNullAndEmptyValues() {
        assertNull(sanitizer.sanitizeBody(null));
        assertEquals("", sanitizer.sanitizeBody(""));
        assertNull(sanitizer.sanitizeText(null));
        assertTrue(sanitizer.sanitizeHeaders(null).isEmpty());
    }

    // Nested JSON tests

    @Test
    void shouldRedactNestedJsonSecrets() {
        String body = """
                {
                    "user": {
                        "username": "student",
                        "credentials": {
                            "password": "secret123",
                            "access_token": "abc123"
                        }
                    }
                }
                """;

        String result = sanitizer.sanitizeBody(body);

        assertTrue(result.contains("student"));
        assertFalse(result.contains("secret123"));
        assertFalse(result.contains("abc123"));
        assertTrue(result.contains("[REDACTED]"));
    }

    @Test
    void shouldRedactSecretsInsideJsonArrays() {
        String body = """
                {
                    "users": [
                        {
                            "username": "alice",
                            "password": "secret1"
                        },
                        {
                            "username": "bob",
                            "password": "secret2"
                        }
                    ]
                }
                """;

        String result = sanitizer.sanitizeBody(body);

        assertTrue(result.contains("alice"));
        assertTrue(result.contains("bob"));
        assertFalse(result.contains("secret1"));
        assertFalse(result.contains("secret2"));
    }

    @Test
    void shouldSanitizeMalformedJsonAsPlainText() {
        String body = "Authorization: Bearer abc.def.ghi";

        String result = sanitizer.sanitizeBody(body);

        assertFalse(result.contains("abc.def.ghi"));
        assertTrue(result.contains("Bearer [REDACTED]"));
    }
}

