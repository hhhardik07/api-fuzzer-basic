
package com.apifuzzer.discovery;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class SeedLoader {

    private final ObjectMapper mapper;
    private final FuzzerConfig config;

    public SeedLoader(FuzzerConfig config) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "FuzzerConfig cannot be null"
            );
        }

        this.config = config;
        this.mapper = new ObjectMapper();
    }

    public List<RequestSpec> load(Path filePath) throws IOException {

        if (filePath == null) {
            throw new IllegalArgumentException(
                    "Manifest path cannot be null"
            );
        }

        List<RequestSpec> requests = mapper.readValue(
                filePath.toFile(),
                new TypeReference<List<RequestSpec>>() {}
        );

        if (requests == null || requests.isEmpty()) {
            throw new IllegalArgumentException(
                    "Manifest contains no requests"
            );
        }

        validateRequests(requests);

        return List.copyOf(requests);
    }

    private void validateRequests(List<RequestSpec> requests) {

        Set<String> requestIds = new HashSet<>();

        for (RequestSpec request : requests) {

            if (request == null) {
                throw new IllegalArgumentException(
                        "Manifest contains a null request"
                );
            }

            if (request.getId() == null
                    || request.getId().isBlank()) {
                throw new IllegalArgumentException(
                        "Every request must have an ID"
                );
            }

            if (!requestIds.add(request.getId())) {
                throw new IllegalArgumentException(
                        "Duplicate request ID: " + request.getId()
                );
            }

            if (request.getMethod() == null
                    || request.getMethod().isBlank()) {
                throw new IllegalArgumentException(
                        "Request method is missing: " + request.getId()
                );
            }

            String method = request.getMethod()
                    .toUpperCase(Locale.ROOT);

            if (!config.getAllowedMethods().contains(method)) {
                throw new IllegalArgumentException(
                        "Unsupported method in request: " + request.getId()
                );
            }

            request.setMethod(method);

            if (request.getUrl() == null
                    || request.getUrl().isBlank()) {
                throw new IllegalArgumentException(
                        "Request URL is missing: " + request.getId()
                );
            }

            URI uri;

            try {
                uri = URI.create(request.getUrl());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "Invalid URL in request: " + request.getId()
                );
            }

            if (uri.getHost() == null
                    || (!"http".equalsIgnoreCase(uri.getScheme())
                    && !"https".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalArgumentException(
                        "Request must contain a valid HTTP or HTTPS URL: "
                                + request.getId()
                );
            }

            if (request.getHeaders() == null) {
                request.setHeaders(new java.util.HashMap<>());
            }

            if (request.getTestStrategy() == null
                    || request.getTestStrategy().isBlank()) {
                request.setTestStrategy("BASELINE");
            }
        }
    }
}

