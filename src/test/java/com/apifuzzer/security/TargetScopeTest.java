package com.apifuzzer.security;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TargetScopeTest {

    private TargetScope createScope() {
        return new TargetScope(
                Set.of("api.example.com"),
                Set.of("GET", "POST"),
                Set.of("/api/v1", "/health")
        );
    }

    @Test
    void shouldAllowApprovedHostMethodAndPath() {
        assertDoesNotThrow(() ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v1/users"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectUnapprovedHost() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://other.example.com/api/v1/users"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectUnapprovedMethod() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v1/users"),
                        "DELETE"
                )
        );
    }

    @Test
    void shouldRejectUnapprovedPath() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://api.example.com/admin/users"),
                        "GET"
                )
        );
    }

    @Test
    void shouldNotTreatSimilarPathAsApprovedPrefix() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v10/users"),
                        "GET"
                )
        );
    }

    @Test
    void shouldAllowExactPathPrefix() {
        assertDoesNotThrow(() ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v1"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectEncodedPathSeparators() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v1%2fadmin"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectDotSegments() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://api.example.com/api/v1/../admin"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectEmbeddedCredentials() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("https://user:pass@api.example.com/api/v1"),
                        "GET"
                )
        );
    }

    @Test
    void shouldRejectNonHttpSchemes() {
        assertThrows(IllegalArgumentException.class, () ->
                createScope().validate(
                        URI.create("file:///etc/passwd"),
                        "GET"
                )
        );
    }
}
