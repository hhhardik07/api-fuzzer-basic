
package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthProfileTest {

    private RequestSpec createRequest() {
        RequestSpec request = new RequestSpec();
        request.setId("test-1");
        request.setMethod("GET");
        request.setUrl("http://localhost:8080/api/test");
        return request;
    }

    @Test
    void shouldApplyBearerToken() {
        RequestSpec request = createRequest();

        AuthProfile profile = AuthProfile.bearer(
                "admin",
                "test-token-123"
        );

        profile.applyTo(request);

        assertEquals(
                "Bearer test-token-123",
                request.getHeaders().get("Authorization")
        );
    }

    @Test
    void shouldApplyCookie() {
        RequestSpec request = createRequest();

        AuthProfile profile = AuthProfile.cookie(
                "student",
                "SESSION=test-session"
        );

        profile.applyTo(request);

        assertEquals(
                "SESSION=test-session",
                request.getHeaders().get("Cookie")
        );
    }

    @Test
    void shouldApplyCustomHeaders() {
        RequestSpec request = createRequest();

        AuthProfile profile = AuthProfile.customHeaders(
                "api-key",
                Map.of(
                        "X-API-Key", "test-key",
                        "X-Client-ID", "test-client"
                )
        );

        profile.applyTo(request);

        assertEquals(
                "test-key",
                request.getHeaders().get("X-API-Key")
        );

        assertEquals(
                "test-client",
                request.getHeaders().get("X-Client-ID")
        );
    }

    @Test
    void shouldPreserveExistingHeaders() {
        RequestSpec request = createRequest();
        request.setHeaders(
                new java.util.HashMap<>(
                        Map.of("Accept", "application/json")
                )
        );

        AuthProfile profile = AuthProfile.bearer(
                "student",
                "test-token"
        );

        profile.applyTo(request);

        assertEquals(
                "application/json",
                request.getHeaders().get("Accept")
        );

        assertTrue(
                request.getHeaders().containsKey("Authorization")
        );
    }

    @Test
    void shouldRejectEmptyCredentials() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AuthProfile.bearer("test", "")
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> AuthProfile.cookie("test", " ")
        );
    }

    @Test
    void shouldNotExposeCredentialsInToString() {
        String secret = "super-secret-token";

        AuthProfile profile = AuthProfile.bearer(
                "student",
                secret
        );

        assertFalse(profile.toString().contains(secret));
        assertTrue(profile.toString().contains("[REDACTED]"));
    }

    @Test
    void shouldSupportNoAuthentication() {
        RequestSpec request = createRequest();

        AuthProfile profile = AuthProfile.none("anonymous");
        profile.applyTo(request);

        assertTrue(request.getHeaders().isEmpty());
    }
}

