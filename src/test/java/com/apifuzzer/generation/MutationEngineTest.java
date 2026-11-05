
package com.apifuzzer.generation;

import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MutationEngineTest {

    private final MutationEngine engine = new MutationEngine();

    private RequestSpec createSeed(String body) {
        return new RequestSpec(
                "seed-001",
                "POST",
                "http://localhost:8765/api/test",
                new HashMap<>(),
                body,
                "BASELINE"
        );
    }

    @Test
    void shouldGenerateMutationsForJsonObject() {

        RequestSpec seed = createSeed("""
                {
                    "username": "student",
                    "age": 20,
                    "active": true
                }
                """);

        List<RequestSpec> mutations =
                engine.generateMutations(seed);

        assertFalse(mutations.isEmpty());
        assertTrue(mutations.size() <= 50);

        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("NULL")
        ));

        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("MISSING")
        ));
    }

    @Test
    void shouldPreserveOriginalSeed() {

        String originalBody = """
                {"username":"student","age":20}
                """;

        RequestSpec seed = createSeed(originalBody);

        engine.generateMutations(seed);

        assertEquals(originalBody, seed.getBody());
        assertEquals("BASELINE", seed.getTestStrategy());
    }

    @Test
    void shouldGenerateUniqueMutationIds() {

        RequestSpec seed = createSeed("""
                {"username":"student","age":20}
                """);

        List<RequestSpec> mutations =
                engine.generateMutations(seed);

        long uniqueIds = mutations.stream()
                .map(RequestSpec::getId)
                .distinct()
                .count();

        assertEquals(mutations.size(), uniqueIds);
    }

    @Test
    void shouldReturnNoMutationsForEmptyBody() {

        RequestSpec seed = createSeed("");

        List<RequestSpec> mutations =
                engine.generateMutations(seed);

        assertTrue(mutations.isEmpty());
    }

    @Test
    void shouldRejectInvalidJson() {

        RequestSpec seed = createSeed(
                "{\"username\": invalid}"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.generateMutations(seed)
        );
    }

    @Test
    void shouldNotExceedMutationLimit() {

        StringBuilder json = new StringBuilder("{");

        for (int i = 0; i < 30; i++) {
            if (i > 0) {
                json.append(",");
            }

            json.append("\"field")
                    .append(i)
                    .append("\":\"value\"");
        }

        json.append("}");

        RequestSpec seed = createSeed(json.toString());

        List<RequestSpec> mutations =
                engine.generateMutations(seed);

        assertTrue(mutations.size() <= 50);
    }

    @Test
    void shouldMutateNestedObjects() {
        RequestSpec seed = createSeed("""
                {
                    "user": {
                        "name": "alice",
                        "age": 25,
                        "active": true
                    },
                    "settings": {
                        "theme": "dark"
                    }
                }
                """);

        List<RequestSpec> mutations = engine.generateMutations(seed);

        assertFalse(mutations.isEmpty());
        assertTrue(mutations.size() <= 50);

        // Should have mutations targeting nested fields
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("NESTED_")
        ));

        // Should have type confusion on nested object
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("NESTED_NULL") ||
                     m.getTestStrategy().contains("NESTED_EMPTY")
        ));
    }

    @Test
    void shouldMutateArrays() {
        RequestSpec seed = createSeed("""
                {
                    "tags": ["java", "spring", "api"],
                    "scores": [100, 95, 98],
                    "flags": [true, false]
                }
                """);

        List<RequestSpec> mutations = engine.generateMutations(seed);

        assertFalse(mutations.isEmpty());
        assertTrue(mutations.size() <= 50);

        // Should have array mutations
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("ARRAY_")
        ));

        // Should have empty array mutation
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("ARRAY_EMPTY")
        ));

        // Should have element removal
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("ARRAY_REMOVE")
        ));
    }

    @Test
    void shouldMutateQueryParameters() {
        RequestSpec seed = createSeed(
                "{\"id\": 123}",
                "http://localhost:8765/api/test?user=alice&action=read&count=5"
        );

        List<RequestSpec> mutations = engine.generateMutations(seed);

        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("QUERY_")
        ));

        // Missing parameter
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("QUERY_MISSING")
        ));

        // Empty value
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("QUERY_EMPTY")
        ));

        // Type confusion on numeric param
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("QUERY_TYPE_CONFUSION")
        ));
    }

    @Test
    void shouldMutateSafeHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");

        RequestSpec seed = createSeedWithHeaders(
                "{\"id\": 1}",
                headers,
                "http://localhost:8765/api/test"
        );

        List<RequestSpec> mutations = engine.generateMutations(seed);

        // Content-Type variations
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("HEADER_CONTENT_TYPE")
        ));

        // Accept variations
        assertTrue(mutations.stream().anyMatch(
                m -> m.getTestStrategy().contains("HEADER_ACCEPT")
        ));

        // Original seed should be unchanged
        assertEquals("application/json", seed.getHeaders().get("Content-Type"));
    }

    @Test
    void shouldPreserveAuthProfileAcrossMutations() {
        RequestSpec seed = createSeed("{\"user\": \"test\"}");
        seed.setAuthProfile("test-profile");

        List<RequestSpec> mutations = engine.generateMutations(seed);

        for (RequestSpec m : mutations) {
            assertEquals("test-profile", m.getAuthProfile(),
                    "Mutation should preserve auth profile: " + m.getId());
            assertEquals(seed.getId(), m.getSeedId(),
                    "Mutation should carry seedId: " + m.getId());
        }
    }

    @Test
    void shouldNotMutateSecurityCriticalHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token123");
        headers.put("Cookie", "session=abc");
        headers.put("Content-Type", "application/json");

        RequestSpec seed = createSeedWithHeaders(
                "{\"id\": 1}",
                headers,
                "http://localhost:8765/api/test"
        );

        List<RequestSpec> mutations = engine.generateMutations(seed);

        // Authorization and Cookie should never be mutated
        for (RequestSpec m : mutations) {
            assertEquals("Bearer token123", m.getHeaders().get("Authorization"),
                    "Authorization must not be mutated");
            assertEquals("session=abc", m.getHeaders().get("Cookie"),
                    "Cookie must not be mutated");
        }
    }

    private RequestSpec createSeed(String body, String url) {
        return new RequestSpec(
                "seed-001",
                "GET",
                url,
                new HashMap<>(),
                body,
                "BASELINE"
        );
    }

    private RequestSpec createSeedWithHeaders(String body, Map<String, String> headers, String url) {
        return new RequestSpec(
                "seed-001",
                "POST",
                url,
                headers,
                body,
                "BASELINE"
        );
    }
}

