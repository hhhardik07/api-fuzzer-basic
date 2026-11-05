
package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthProfileManagerTest {

    @Test
    void shouldRegisterProfiles() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("anonymous"));
        manager.register(AuthProfile.bearer("student", "student-token"));

        assertEquals(2, manager.size());
        assertTrue(manager.getProfileNames().contains("student"));
        assertTrue(manager.getProfileNames().contains("anonymous"));
    }

    @Test
    void shouldRejectDuplicateProfiles() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("student"));

        assertThrows(
                IllegalArgumentException.class,
                () -> manager.register(
                        AuthProfile.bearer("student", "another-token")
                )
        );
    }

    @Test
    void shouldActivateDifferentProfiles() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("anonymous"));
        manager.register(AuthProfile.bearer("student", "student-token"));

        manager.activate("student");

        assertEquals(
                "student",
                manager.getActiveProfile().getName()
        );
    }

    @Test
    void shouldApplyActiveProfileToRequest() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("anonymous"));
        manager.register(AuthProfile.bearer("student", "student-token"));

        manager.activate("student");

        RequestSpec request = new RequestSpec();
        request.setHeaders(new java.util.HashMap<>());

        manager.applyActiveProfile(request);

        assertEquals(
                "Bearer student-token",
                request.getHeaders().get("Authorization")
        );
    }

    @Test
    void shouldRejectUnknownProfile() {
        AuthProfileManager manager = new AuthProfileManager();

        assertThrows(
                IllegalArgumentException.class,
                () -> manager.activate("unknown")
        );
    }

    @Test
    void shouldRemoveActiveProfileAndSelectAnother() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("anonymous"));
        manager.register(AuthProfile.bearer("student", "student-token"));

        manager.activate("student");

        assertTrue(manager.remove("student"));

        assertEquals(
                "anonymous",
                manager.getActiveProfile().getName()
        );
    }

    @Test
    void shouldHaveNoActiveProfileAfterRemovingLastProfile() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.none("anonymous"));

        assertTrue(manager.remove("anonymous"));

        assertThrows(
                IllegalStateException.class,
                manager::getActiveProfile
        );
    }

    @Test
    void shouldNotModifyManagerThroughProfileNames() {
        AuthProfileManager manager = new AuthProfileManager();
        manager.register(AuthProfile.none("anonymous"));

        assertThrows(
                UnsupportedOperationException.class,
                () -> manager.getProfileNames().clear()
        );

        assertEquals(1, manager.size());
    }

    @Test
    void shouldKeepCredentialsSeparateWhenSwitchingProfiles() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(AuthProfile.bearer("student", "student-token"));
        manager.register(AuthProfile.bearer("admin", "admin-token"));

        RequestSpec studentRequest = new RequestSpec();
        studentRequest.setHeaders(new java.util.HashMap<>());

        manager.activate("student");
        manager.applyActiveProfile(studentRequest);

        RequestSpec adminRequest = new RequestSpec();
        adminRequest.setHeaders(new java.util.HashMap<>());

        manager.activate("admin");
        manager.applyActiveProfile(adminRequest);

        assertEquals(
                "Bearer student-token",
                studentRequest.getHeaders().get("Authorization")
        );

        assertEquals(
                "Bearer admin-token",
                adminRequest.getHeaders().get("Authorization")
        );
    }
}

