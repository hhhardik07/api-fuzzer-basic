package com.apifuzzer.generation;

import com.apifuzzer.model.RequestSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class StructuralMutator implements MutationStrategy {

    private static final String[] HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"};
    private static final String[] CONTENT_TYPES = {
        "application/json", "application/xml", "application/x-www-form-urlencoded",
        "multipart/form-data", "text/plain", "application/octet-stream"
    };

    private final Random random = ThreadLocalRandom.current();

    @Override
    public List<RequestSpec> mutate(RequestSpec original, int count) {
        List<RequestSpec> mutations = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            mutations.add(createMutation(original));
        }
        return mutations;
    }

    private RequestSpec createMutation(RequestSpec original) {
        RequestSpec mutated = deepCopy(original);
        int strategy = random.nextInt(6);

        String mutationType = "";
        switch (strategy) {
            case 0 -> { mutateMethod(mutated); mutationType = "METHOD"; }
            case 1 -> { mutateContentType(mutated); mutationType = "CONTENT_TYPE"; }
            case 2 -> { mutatePathParameters(mutated); mutationType = "PATH_PARAMS"; }
            case 3 -> { mutateQueryParameters(mutated); mutationType = "QUERY_PARAMS"; }
            case 4 -> { removeHeaders(mutated); mutationType = "REMOVE_HEADERS"; }
            case 5 -> { addDuplicateHeaders(mutated); mutationType = "DUPLICATE_HEADERS"; }
        }

        mutated.setId(original.getId() + "-struct-" + System.nanoTime());
        mutated.setTestStrategy(getName() + "_" + mutationType);
        mutated.setSeedId(original.getSeedId());
        return mutated;
    }

    private void mutateMethod(RequestSpec spec) {
        String current = spec.getMethod();
        String next;
        do {
            next = HTTP_METHODS[random.nextInt(HTTP_METHODS.length)];
        } while (next.equalsIgnoreCase(current));
        spec.setMethod(next);

        if (("GET".equalsIgnoreCase(next) || "HEAD".equalsIgnoreCase(next)) && spec.getBody() != null) {
            spec.setBody(null);
            Map<String, String> headers = new java.util.HashMap<>(spec.getHeaders());
            headers.remove("Content-Type");
            headers.remove("Content-Length");
            spec.setHeaders(headers);
        }
    }

    private void mutateContentType(RequestSpec spec) {
        Map<String, String> headers = new java.util.HashMap<>(spec.getHeaders());
        String newType = CONTENT_TYPES[random.nextInt(CONTENT_TYPES.length)];
        headers.put("Content-Type", newType);
        spec.setHeaders(headers);
    }

    private void mutatePathParameters(RequestSpec spec) {
        String url = spec.getUrl();
        if (url == null) return;

        String[] parts = url.split("\\?");
        String path = parts[0];
        String query = parts.length > 1 ? "?" + parts[1] : "";

        String[] segments = path.split("/");
        StringBuilder newPath = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) newPath.append("/");
            if (segments[i].matches("\\d+") && random.nextBoolean()) {
                newPath.append(random.nextInt(100000));
            } else if (segments[i].matches("[a-fA-F0-9-]{36}") && random.nextBoolean()) {
                newPath.append(java.util.UUID.randomUUID());
            } else {
                newPath.append(segments[i]);
            }
        }
        spec.setUrl(newPath.toString() + query);
    }

    private void mutateQueryParameters(RequestSpec spec) {
        String url = spec.getUrl();
        if (url == null) return;

        String[] parts = url.split("\\?", 2);
        String path = parts[0];
        String query = parts.length > 1 ? parts[1] : "";

        StringBuilder newQuery = new StringBuilder();
        if (!query.isEmpty()) {
            String[] params = query.split("&");
            for (String param : params) {
                if (newQuery.length() > 0) newQuery.append("&");
                String[] kv = param.split("=", 2);
                if (kv.length == 2 && random.nextBoolean()) {
                    newQuery.append(kv[0]).append("=").append(mutateValue(kv[1]));
                } else {
                    newQuery.append(param);
                }
            }
        }

        if (random.nextBoolean()) {
            if (newQuery.length() > 0) newQuery.append("&");
            newQuery.append("fuzz").append(random.nextInt(1000)).append("=").append(random.nextInt(10000));
        }

        spec.setUrl(path + (newQuery.isEmpty() ? "" : "?" + newQuery));
    }

    private String mutateValue(String value) {
        int type = random.nextInt(5);
        return switch (type) {
            case 0 -> value + "'";
            case 1 -> value + "<script>alert(1)</script>";
            case 2 -> String.valueOf(random.nextInt(100000));
            case 3 -> "true";
            case 4 -> "";
            default -> value;
        };
    }

    private void removeHeaders(RequestSpec spec) {
        Map<String, String> headers = new java.util.HashMap<>(spec.getHeaders());
        if (!headers.isEmpty() && random.nextBoolean()) {
            String[] keys = headers.keySet().toArray(new String[0]);
            headers.remove(keys[random.nextInt(keys.length)]);
            spec.setHeaders(headers);
        }
    }

    private void addDuplicateHeaders(RequestSpec spec) {
        Map<String, String> headers = new java.util.HashMap<>(spec.getHeaders());
        if (!headers.isEmpty()) {
            String[] keys = headers.keySet().toArray(new String[0]);
            String key = keys[random.nextInt(keys.length)];
            headers.put(key + "_dup", headers.get(key));
            spec.setHeaders(headers);
        }
    }

    private RequestSpec deepCopy(RequestSpec original) {
        RequestSpec copy = new RequestSpec();
        copy.setId(original.getId());
        copy.setMethod(original.getMethod());
        copy.setUrl(original.getUrl());
        copy.setHeaders(new java.util.HashMap<>(original.getHeaders()));
        copy.setBody(original.getBody());
        copy.setTestStrategy(original.getTestStrategy());
        copy.setAuthProfile(original.getAuthProfile());
        copy.setSeedId(original.getSeedId());
        return copy;
    }

    @Override
    public String getName() {
        return "STRUCTURAL_MUTATOR";
    }

    @Override
    public String getDescription() {
        return "Mutates HTTP structure: method, content-type, path/query params, headers";
    }
}