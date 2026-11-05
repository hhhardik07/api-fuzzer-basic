package com.apifuzzer.config;

import com.apifuzzer.auth.AuthProfile;
import com.apifuzzer.auth.AuthProfileManager;
import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CollegePortalConfigTest {

    @Test
    void shouldValidateAndBuildConfigForValidInput() {
        CollegePortalConfig config = createValidConfig();

        // Should not throw
        config.validate();

        AuthProfileManager authManager = new AuthProfileManager();
        FuzzerConfig fuzzerConfig = config.toFuzzerConfig(Path.of("/tmp/report.json"), authManager);

        assertEquals("portal.example.edu", fuzzerConfig.getAllowedHosts().iterator().next());
        assertEquals(1, fuzzerConfig.getRequestsPerSecond());
        assertEquals(50, fuzzerConfig.getMaxRequestsPerSession());
        assertEquals(Path.of("/tmp/report.json"), fuzzerConfig.getReportOutputPath());
        assertTrue(authManager.getProfileNames().contains("college-portal"));
    }

    @Test
    void shouldBuildSeedRequestsWithCorrectUrlsAndAuth() {
        CollegePortalConfig config = createValidConfig();

        List<RequestSpec> seeds = config.buildSeedRequests();

        // createValidConfig creates 1 seed
        assertEquals(1, seeds.size());

        for (RequestSpec seed : seeds) {
            assertTrue(seed.getUrl().startsWith("https://portal.example.edu/"));
            assertEquals("college-portal", seed.getAuthProfile());
            assertEquals("application/json", seed.getHeaders().get("Accept"));
        }

        // Check specific seed
        assertTrue(seeds.stream().anyMatch(s -> s.getId().equals("seed-1") && s.getUrl().endsWith("/api/v1/profile/me")));
    }

    @Test
    void shouldRejectMissingHostname() {
        CollegePortalConfig config = createValidConfig();
        config.setPortalHostname(null);

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldRejectEmptyPathPrefixes() {
        CollegePortalConfig config = createValidConfig();
        config.setApprovedPathPrefixes(List.of());

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldRejectMissingDemoSeeds() {
        CollegePortalConfig config = createValidConfig();
        config.setDemoSeeds(List.of());

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldRejectSeedWithoutId() {
        CollegePortalConfig config = createValidConfig();
        config.getDemoSeeds().get(0).setId("");

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldRejectSeedWithoutPath() {
        CollegePortalConfig config = createValidConfig();
        config.getDemoSeeds().get(0).setPath("");

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldRejectMissingTestAccountCredential() {
        CollegePortalConfig config = createValidConfig();
        config.getTestAccount().setCredential("");

        assertThrows(IllegalStateException.class, config::validate);
    }

    @Test
    void shouldSupportCookieAuth() {
        CollegePortalConfig config = createValidConfig();
        config.getTestAccount().setAuthType("COOKIE");
        config.getTestAccount().setCredential("session=abc123");

        AuthProfileManager authManager = new AuthProfileManager();
        config.toFuzzerConfig(Path.of("/tmp/report.json"), authManager);

        AuthProfile profile = authManager.getProfile("college-portal");
        assertEquals(AuthProfile.AuthType.COOKIE, profile.getAuthType());
    }

    @Test
    void shouldSupportCustomHeadersAuth() {
        CollegePortalConfig config = createValidConfig();
        config.getTestAccount().setAuthType("CUSTOM_HEADERS");
        Map<String, String> custom = new HashMap<>();
        custom.put("X-API-Key", "test-key");
        config.getTestAccount().setCustomHeaders(custom);

        AuthProfileManager authManager = new AuthProfileManager();
        config.toFuzzerConfig(Path.of("/tmp/report.json"), authManager);

        AuthProfile profile = authManager.getProfile("college-portal");
        assertEquals(AuthProfile.AuthType.CUSTOM_HEADERS, profile.getAuthType());
        // Custom headers are applied at request execution time, not directly accessible
    }

    @Test
    void shouldRejectInvalidAuthType() {
        CollegePortalConfig config = createValidConfig();
        config.getTestAccount().setAuthType("UNKNOWN");

        AuthProfileManager authManager = new AuthProfileManager();
        assertThrows(IllegalStateException.class, () -> config.toFuzzerConfig(Path.of("/tmp/report.json"), authManager));
    }

    @Test
    void shouldRejectCustomHeadersAuthWithoutHeaders() {
        CollegePortalConfig config = createValidConfig();
        config.getTestAccount().setAuthType("CUSTOM_HEADERS");
        config.getTestAccount().setCustomHeaders(null);

        AuthProfileManager authManager = new AuthProfileManager();
        assertThrows(IllegalStateException.class, () -> config.toFuzzerConfig(Path.of("/tmp/report.json"), authManager));
    }

    private CollegePortalConfig createValidConfig() {
        CollegePortalConfig config = new CollegePortalConfig();
        config.setPortalHostname("portal.example.edu");
        config.setApprovedPathPrefixes(List.of("/api/v1/profile", "/api/v1/courses"));
        config.setApprovedMethods(Set.of("GET"));
        config.setMaxRequestsPerSession(50);
        config.setRequestsPerSecond(1);
        config.setRequestTimeoutSeconds(10);

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        config.setTestHeaders(headers);

        CollegePortalConfig.AuthProfileConfig account = new CollegePortalConfig.AuthProfileConfig();
        account.setProfileName("college-portal");
        account.setAuthType("BEARER");
        account.setCredential("test-token");
        config.setTestAccount(account);

        CollegePortalConfig.RequestSpecConfig seed = new CollegePortalConfig.RequestSpecConfig();
        seed.setId("seed-1");
        seed.setMethod("GET");
        seed.setPath("/api/v1/profile/me");
        config.setDemoSeeds(List.of(seed));

        return config;
    }
}