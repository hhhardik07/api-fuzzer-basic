
package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthProfileResolverTest {

    private RequestSpec createRequest(String profileName) {
        RequestSpec request = new RequestSpec();

        request.setId("request-1");
        request.setMethod("GET");
        request.setUrl("http://localhost:8080/api/test");
        request.setAuthProfile(profileName);
        request.setHeaders(new HashMap<>());

        return request;
    }

    @Test
    void shouldApplyRequestedProfileToCopy() {
        AuthProfileManager manager = new AuthProfileManager();
        manager.register(
                AuthProfile.bearer("admin", "admin-token")
        );

        AuthProfileResolver resolver = new AuthProfileResolver(manager);
        RequestSpec original = createRequest("admin");

        RequestSpec resolved = resolver.resolveRequest(original);

        assertEquals(
                "Bearer admin-token",
                resolved.getHeaders().get("Authorization")
        );

        assertFalse(original.getHeaders().containsKey("Authorization"));
    }

    @Test
    void shouldLeaveAnonymousRequestUnchanged() {
        AuthProfileResolver resolver = new AuthProfileResolver(
                new AuthProfileManager()
        );

        RequestSpec original = createRequest(null);
        RequestSpec resolved = resolver.resolveRequest(original);

        assertNotSame(original, resolved);
        assertTrue(resolved.getHeaders().isEmpty());
        assertTrue(original.getHeaders().isEmpty());
    }

    @Test
    void shouldRejectUnknownProfile() {
        AuthProfileResolver resolver = new AuthProfileResolver(
                new AuthProfileManager()
        );

        RequestSpec request = createRequest("unknown");

        assertThrows(
                IllegalArgumentException.class,
                () -> resolver.resolveRequest(request)
        );
    }

    @Test
    void shouldNotDependOnActiveProfile() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(
                AuthProfile.bearer("student", "student-token")
        );

        manager.register(
                AuthProfile.bearer("admin", "admin-token")
        );

        manager.activate("student");

        AuthProfileResolver resolver = new AuthProfileResolver(manager);
        RequestSpec request = createRequest("admin");

        RequestSpec resolved = resolver.resolveRequest(request);

        assertEquals(
                "Bearer admin-token",
                resolved.getHeaders().get("Authorization")
        );
    }

    @Test
    void shouldPreserveOriginalHeadersAndRequestData() {
        AuthProfileManager manager = new AuthProfileManager();
        manager.register(
                AuthProfile.bearer("student", "student-token")
        );

        AuthProfileResolver resolver = new AuthProfileResolver(manager);

        RequestSpec original = createRequest("student");
        original.setBody("{\"name\":\"test\"}");
        original.getHeaders().put("Accept", "application/json");

        RequestSpec resolved = resolver.resolveRequest(original);

        assertEquals(original.getId(), resolved.getId());
        assertEquals(original.getMethod(), resolved.getMethod());
        assertEquals(original.getUrl(), resolved.getUrl());
        assertEquals(original.getBody(), resolved.getBody());

        assertEquals(
                "application/json",
                original.getHeaders().get("Accept")
        );

        assertFalse(original.getHeaders().containsKey("Authorization"));
        assertEquals(
                "Bearer student-token",
                resolved.getHeaders().get("Authorization")
        );
    }

    @Test
    void shouldUseIndependentHeaderMaps() {
        AuthProfileResolver resolver = new AuthProfileResolver(
                new AuthProfileManager()
        );

        RequestSpec original = createRequest(null);
        RequestSpec resolved = resolver.resolveRequest(original);

        resolved.getHeaders().put("X-Test", "modified");

        assertFalse(original.getHeaders().containsKey("X-Test"));
    }
}

