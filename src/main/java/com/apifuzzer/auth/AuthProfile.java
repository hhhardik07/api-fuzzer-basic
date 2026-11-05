package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class AuthProfile {

    public enum AuthType {
        NONE,
        BEARER,
        COOKIE,
        CUSTOM_HEADERS
    }

    private final String name;
    private final AuthType authType;
    private final String credential;
    private final Map<String, String> customHeaders;

    private AuthProfile(
            String name,
            AuthType authType,
            String credential,
            Map<String, String> customHeaders
    ) {
        this.name = Objects.requireNonNull(name);
        this.authType = Objects.requireNonNull(authType);
        this.credential = credential;
        this.customHeaders = Map.copyOf(customHeaders);
    }

    public static AuthProfile none(String name) {
        return new AuthProfile(
                name, AuthType.NONE, null, Map.of()
        );
    }

    public static AuthProfile bearer(
            String name,
            String token
    ) {
        requireCredential(token);

        return new AuthProfile(
                name, AuthType.BEARER, token, Map.of()
        );
    }

    public static AuthProfile cookie(
            String name,
            String cookie
    ) {
        requireCredential(cookie);

        return new AuthProfile(
                name, AuthType.COOKIE, cookie, Map.of()
        );
    }

    public static AuthProfile customHeaders(
            String name,
            Map<String, String> headers
    ) {
        Objects.requireNonNull(headers);

        if (headers.isEmpty()) {
            throw new IllegalArgumentException(
                    "Custom headers cannot be empty"
            );
        }

        return new AuthProfile(
                name,
                AuthType.CUSTOM_HEADERS,
                null,
                headers
        );
    }

    private static void requireCredential(String credential) {
        if (credential == null || credential.isBlank()) {
            throw new IllegalArgumentException(
                    "Credential cannot be empty"
            );
        }
    }

    public void applyTo(RequestSpec request) {
        Objects.requireNonNull(request);

        Map<String, String> headers = request.getHeaders();

        if (headers == null) {
            headers = new HashMap<>();
            request.setHeaders(headers);
        }

        switch (authType) {
            case NONE -> {
                // No authentication headers required.
            }

            case BEARER -> headers.put(
                    "Authorization",
                    "Bearer " + credential
            );

            case COOKIE -> headers.put(
                    "Cookie",
                    credential
            );

            case CUSTOM_HEADERS -> {
                for (Map.Entry<String, String> entry
                        : customHeaders.entrySet()) {

                    headers.put(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    public String getName() {
        return name;
    }

    public AuthType getAuthType() {
        return authType;
    }

    @Override
    public String toString() {
        return "AuthProfile{" +
                "name='" + name + '\'' +
                ", authType=" + authType +
                ", credentials='[REDACTED]'" +
                '}';
    }
}
