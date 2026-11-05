
package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;

import java.util.HashMap;
import java.util.Objects;

public class AuthProfileResolver {

    private final AuthProfileManager profileManager;

    public AuthProfileResolver(AuthProfileManager profileManager) {
        this.profileManager = Objects.requireNonNull(
                profileManager,
                "Profile manager cannot be null"
        );
    }

    /**
     * Creates an independent request copy and applies authentication
     * to that copy. The original request remains unchanged.
     */
    public RequestSpec resolveRequest(RequestSpec original) {
        Objects.requireNonNull(original, "Request cannot be null");

        RequestSpec resolved = copyRequest(original);

        String profileName = original.getAuthProfile();

        // No profile means anonymous request.
        if (profileName == null || profileName.isBlank()) {
            return resolved;
        }

        AuthProfile profile = profileManager.getProfile(profileName);
        profile.applyTo(resolved);

        return resolved;
    }

    private RequestSpec copyRequest(RequestSpec original) {
        RequestSpec copy = new RequestSpec();

        copy.setId(original.getId());
        copy.setMethod(original.getMethod());
        copy.setUrl(original.getUrl());
        copy.setBody(original.getBody());
        copy.setTestStrategy(original.getTestStrategy());
        copy.setAuthProfile(original.getAuthProfile());

        if (original.getHeaders() != null) {
            copy.setHeaders(new HashMap<>(original.getHeaders()));
        } else {
            copy.setHeaders(new HashMap<>());
        }

        return copy;
    }
}

