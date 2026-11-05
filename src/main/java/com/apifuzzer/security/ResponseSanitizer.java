
package com.apifuzzer.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class ResponseSanitizer {

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key"
    );

    private static final Set<String> SENSITIVE_JSON_KEYS = Set.of(
            "password",
            "password_hash",
            "access_token",
            "refresh_token",
            "token",
            "secret",
            "client_secret",
            "api_secret",
            "session_secret",
            "private_key"
    );

    private static final Pattern BEARER_PATTERN =
            Pattern.compile(
                    "(?i)Bearer\\s+[A-Za-z0-9._~+/-]+=*"
            );

    private static final Pattern BASIC_PATTERN =
            Pattern.compile(
                    "(?i)Basic\\s+[A-Za-z0-9+/=]+"
            );

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, List<String>> sanitizeHeaders(
            Map<String, List<String>> headers
    ) {
        if (headers == null) {
            return Map.of();
        }

        Map<String, List<String>> sanitized = new HashMap<>();

        headers.forEach((name, values) -> {
            if (name == null) {
                return;
            }

            String normalized = name.toLowerCase(Locale.ROOT);

            if (SENSITIVE_HEADERS.contains(normalized)) {
                sanitized.put(name, List.of("[REDACTED]"));
            } else {
                sanitized.put(
                        name,
                        values == null
                                ? List.of()
                                : values.stream()
                                        .map(this::sanitizeText)
                                        .toList()
                );
            }
        });

        return Map.copyOf(sanitized);
    }

    public String sanitizeBody(String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }

        try {
            JsonNode root = objectMapper.readTree(body);

            if (root == null) {
                return sanitizeText(body);
            }

            redactJsonNode(root);

            return objectMapper.writeValueAsString(root);

        } catch (Exception e) {
            // Non-JSON or malformed JSON: use text sanitization.
            return sanitizeText(body);
        }
    }

    private void redactJsonNode(JsonNode node) {

        if (node instanceof ObjectNode objectNode) {

            var fields = objectNode.fields();

            while (fields.hasNext()) {
                var entry = fields.next();

                String key = entry.getKey()
                        .toLowerCase(Locale.ROOT);

                if (SENSITIVE_JSON_KEYS.contains(key)) {
                    objectNode.set(
                            entry.getKey(),
                            TextNode.valueOf("[REDACTED]")
                    );
                } else {
                    redactJsonNode(entry.getValue());
                }
            }

        } else if (node instanceof ArrayNode arrayNode) {

            for (JsonNode child : arrayNode) {
                redactJsonNode(child);
            }
        }
    }

    public String sanitizeText(String text) {
        if (text == null) {
            return null;
        }

        String sanitized = BEARER_PATTERN.matcher(text)
                .replaceAll("Bearer [REDACTED]");

        sanitized = BASIC_PATTERN.matcher(sanitized)
                .replaceAll("Basic [REDACTED]");

        return sanitized;
    }
}

