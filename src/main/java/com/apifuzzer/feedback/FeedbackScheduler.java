package com.apifuzzer.feedback;

import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.regex.Pattern;

public class FeedbackScheduler {

    private static class ScheduledRequest {
        private final RequestSpec request;
        private final double priority;
        private final long sequence;

        private ScheduledRequest(
                RequestSpec request,
                double priority,
                long sequence
        ) {
            this.request = request;
            this.priority = priority;
            this.sequence = sequence;
        }
    }

    private final PriorityQueue<ScheduledRequest> queue =
            new PriorityQueue<>(
                    Comparator.comparingDouble(
                            (ScheduledRequest item) -> item.priority
                    ).reversed().thenComparingLong(item -> item.sequence)
            );

    private final Map<String, Double> strategyScores =
            new HashMap<>();

    private final Set<String> observedSignatures =
            new HashSet<>();

    private final Set<String> pendingMutationIds =
            new HashSet<>();

    private final ObjectMapper mapper = new ObjectMapper();

    // Volatile field patterns to ignore when computing structural novelty
    private static final Set<String> VOLATILE_JSON_FIELDS = Set.of(
            "timestamp", "requestId", "traceId", "spanId", "sessionId",
            "correlationId", "nonce", "generatedAt", "createdAt", "updatedAt",
            "expiresAt", "id", "uuid", "token", "etag", "version"
    );

    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile(
            "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})?"
    );

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private long sequence = 0;

    public synchronized void submit(RequestSpec request) {

        if (request == null) {
            throw new IllegalArgumentException(
                    "Request cannot be null"
            );
        }

        String mutationId = request.getId();

        // Prevent duplicate mutations from accumulating
        if (!pendingMutationIds.add(mutationId)) {
            return;
        }

        String strategy = extractStrategy(request);

        double priority = 1.0
                + strategyScores.getOrDefault(strategy, 0.0);

        queue.add(new ScheduledRequest(
                request,
                priority,
                sequence++
        ));
    }

    public synchronized void submitAll(
            List<RequestSpec> requests
    ) {

        if (requests == null) {
            throw new IllegalArgumentException(
                    "Request list cannot be null"
            );
        }

        for (RequestSpec request : requests) {
            submit(request);
        }
    }

    public synchronized RequestSpec pollNext() {

        ScheduledRequest next = queue.poll();

        if (next != null) {
            pendingMutationIds.remove(next.request.getId());
        }

        return next == null ? null : next.request;
    }

    public synchronized void recordOutcome(
            RequestSpec request,
            Observation baseline,
            Observation actual,
            List<Finding> findings
    ) {

        if (request == null || actual == null) {
            throw new IllegalArgumentException(
                    "Request and observation are required"
            );
        }

        String strategy = extractStrategy(request);

        double reward = 0.0;

        if (actual.getErrorMessage() != null) {
            // Execution failures are not evidence of interesting behavior.
            strategyScores.put(
                    strategy,
                    strategyScores.getOrDefault(strategy, 0.0) - 0.5
            );
            return;
        }

        String signature = createNormalizedSignature(actual);

        boolean novel = observedSignatures.add(signature);

        if (novel) {
            reward += 2.0;
        } else {
            reward -= 0.5;
        }

        if (baseline != null
                && baseline.getStatusCode() != actual.getStatusCode()) {
            reward += 1.0;
        }

        if (findings != null && !findings.isEmpty()) {
            reward += Math.min(findings.size() * 3.0, 9.0);
        }

        // Bound strategy scores to prevent monopolization
        double newScore = strategyScores.getOrDefault(strategy, 0.0) + reward;
        strategyScores.put(strategy, clamp(newScore, -10.0, 20.0));
    }

    private String extractStrategy(RequestSpec request) {

        String strategy = request.getTestStrategy();

        if (strategy == null || !strategy.startsWith("MUTATION:")) {
            return "BASELINE";
        }

        String mutation = strategy.substring("MUTATION:".length());

        int separator = mutation.indexOf('_');

        if (separator > 0) {
            return mutation.substring(0, separator);
        }

        return mutation;
    }

    private String createNormalizedSignature(Observation observation) {

        StringBuilder signature = new StringBuilder();

        signature.append(observation.getStatusCode());

        if (observation.getResponseHeaders() != null) {
            observation.getResponseHeaders().forEach((key, values) -> {
                if (key.equalsIgnoreCase("content-type")) {
                    signature.append("|").append(values);
                }
            });
        }

        String body = observation.getResponseBody();
        if (body != null && !body.isBlank()) {
            String normalized = normalizeJsonBody(body);
            signature.append("|").append(normalized);
        }

        return sha256(signature.toString());
    }

    private String normalizeJsonBody(String body) {
        try {
            JsonNode node = mapper.readTree(body);
            JsonNode normalized = deepNormalize(node);
            // Compact representation for consistent hashing
            return mapper.writeValueAsString(normalized);
        } catch (Exception e) {
            // Non-JSON or malformed: normalize timestamps/UUIDs in text
            return normalizeTextBody(body);
        }
    }

    private JsonNode deepNormalize(JsonNode node) {
        if (node == null) {
            return NullNode.instance;
        }

        if (node.isObject()) {
            ObjectNode normalized = mapper.createObjectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey();
                JsonNode value = field.getValue();

                if (VOLATILE_JSON_FIELDS.contains(key.toLowerCase())) {
                    // Replace volatile field values with placeholder
                    normalized.set(key, TextNode.valueOf("<VOLATILE>"));
                } else {
                    normalized.set(key, deepNormalize(value));
                }
            }
            return normalized;

        } else if (node.isArray()) {
            ArrayNode normalized = mapper.createArrayNode();
            for (JsonNode element : node) {
                normalized.add(deepNormalize(element));
            }
            return normalized;

        } else if (node.isTextual()) {
            String text = node.asText();
            // Replace timestamps
            text = TIMESTAMP_PATTERN.matcher(text).replaceAll("<TIMESTAMP>");
            // Replace UUIDs
            text = UUID_PATTERN.matcher(text).replaceAll("<UUID>");
            return TextNode.valueOf(text);

        } else {
            return node.deepCopy();
        }
    }

    private String normalizeTextBody(String body) {
        String normalized = TIMESTAMP_PATTERN.matcher(body).replaceAll("<TIMESTAMP>");
        normalized = UUID_PATTERN.matcher(normalized).replaceAll("<UUID>");
        // Normalize whitespace
        normalized = normalized.replaceAll("\\s+", " ").trim();
        return normalized;
    }

    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private String sha256(String value) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    value.getBytes(StandardCharsets.UTF_8)
            );

            StringBuilder result = new StringBuilder();

            for (byte b : hash) {
                result.append(String.format("%02x", b));
            }

            return result.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable", e
            );
        }
    }

    public synchronized double getStrategyScore(String strategy) {
        return strategyScores.getOrDefault(strategy, 0.0);
    }

    public synchronized Map<String, Double> getStrategyScores() {
        return Map.copyOf(strategyScores);
    }

    public synchronized int getPendingCount() {
        return queue.size();
    }

    public synchronized boolean hasPendingRequests() {
        return !queue.isEmpty();
    }
}