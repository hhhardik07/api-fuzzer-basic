
package com.apifuzzer.auth;

import com.apifuzzer.model.RequestSpec;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class AuthProfileManager {

    private final Map<String, AuthProfile> profiles =
            new LinkedHashMap<>();

    private String activeProfileName;

    public void register(AuthProfile profile) {
        Objects.requireNonNull(profile, "Profile cannot be null");

        String name = profile.getName();

        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(
                    "Profile name cannot be empty"
            );
        }

        if (profiles.containsKey(name)) {
            throw new IllegalArgumentException(
                    "Profile already exists: " + name
            );
        }

        profiles.put(name, profile);

        if (activeProfileName == null) {
            activeProfileName = name;
        }
    }

    public AuthProfile getProfile(String name) {
        AuthProfile profile = profiles.get(name);

        if (profile == null) {
            throw new IllegalArgumentException(
                    "Unknown authentication profile: " + name
            );
        }

        return profile;
    }

    public void activate(String name) {
        getProfile(name);
        activeProfileName = name;
    }

    public AuthProfile getActiveProfile() {
        if (activeProfileName == null) {
            throw new IllegalStateException(
                    "No authentication profile is registered"
            );
        }

        return getProfile(activeProfileName);
    }

    public void applyActiveProfile(RequestSpec request) {
        getActiveProfile().applyTo(request);
    }

    public boolean remove(String name) {
        AuthProfile removed = profiles.remove(name);

        if (removed == null) {
            return false;
        }

        if (Objects.equals(activeProfileName, name)) {
            activeProfileName = profiles.keySet()
                    .stream()
                    .findFirst()
                    .orElse(null);
        }

        return true;
    }

    public Collection<String> getProfileNames() {
        return Collections.unmodifiableSet(
                profiles.keySet()
        );
    }

    public int size() {
        return profiles.size();
    }

    public boolean isEmpty() {
        return profiles.isEmpty();
    }
}

