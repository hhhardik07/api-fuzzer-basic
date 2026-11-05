package com.apifuzzer.generation;

import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

public class MutationEngine {

    private static final int MAX_MUTATIONS = 50;
    private static final int LONG_STRING_LENGTH = 256;
    private static final int MAX_NESTING_DEPTH = 5;
    private static final int MAX_ARRAY_SIZE = 20;
    private static final int MAX_PAYLOAD_SIZE = 10000;

    private final ObjectMapper mapper = new ObjectMapper();

    public List<RequestSpec> generateMutations(RequestSpec seed) {

        if (seed == null) {
            throw new IllegalArgumentException(
                    "Seed request cannot be null"
            );
        }

        if (seed.getBody() == null || seed.getBody().isBlank()) {
            return generateQueryAndHeaderMutations(seed);
        }

        JsonNode parsed;

        try {
            parsed = mapper.readTree(seed.getBody());
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(
                    "Seed body is not valid JSON", e
            );
        }

        if (!(parsed instanceof ObjectNode root)) {
            return generateQueryAndHeaderMutations(seed);
        }

        List<RequestSpec> mutations = new ArrayList<>();

        // Phase 1: JSON body mutations (existing + new nested/array support)
        mutateObjectRecursive(root, "", 0, seed, mutations);

        // Phase 2: Query parameter mutations
        mutations.addAll(generateQueryAndHeaderMutations(seed));

        return List.copyOf(mutations);
    }

    private void mutateObjectRecursive(
            ObjectNode node,
            String pathPrefix,
            int depth,
            RequestSpec seed,
            List<RequestSpec> mutations
    ) {
        if (depth > MAX_NESTING_DEPTH || mutations.size() >= MAX_MUTATIONS) {
            return;
        }

        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();

        while (fields.hasNext() && mutations.size() < MAX_MUTATIONS) {
            Map.Entry<String, JsonNode> field = fields.next();
            String fieldName = field.getKey();
            String fullPath = pathPrefix.isEmpty() ? fieldName : pathPrefix + "." + fieldName;
            JsonNode originalValue = field.getValue();

            // Skip if this would exceed payload size limit
            if (estimatePayloadSize(node) > MAX_PAYLOAD_SIZE) {
                return;
            }

            // 1. Null replacement
            addMutation(seed, node, fieldName, NullNode.instance, "NULL_" + fullPath, mutations);

            // 2. Missing field
            ObjectNode missingField = node.deepCopy();
            missingField.remove(fieldName);
            addMutation(seed, missingField, "MISSING_" + fullPath, mutations);

            if (originalValue.isTextual()) {
                // 3. Empty string
                addMutation(seed, node, fieldName, TextNode.valueOf(""), "EMPTY_STRING_" + fullPath, mutations);

                // 4. Oversized string
                addMutation(seed, node, fieldName, TextNode.valueOf("A".repeat(LONG_STRING_LENGTH)),
                        "LONG_STRING_" + fullPath, mutations);

                // 5. Type confusion - number
                addMutation(seed, node, fieldName, IntNode.valueOf(123), "TYPE_CONFUSION_NUM_" + fullPath, mutations);

                // 6. Type confusion - boolean
                addMutation(seed, node, fieldName, BooleanNode.valueOf(true), "TYPE_CONFUSION_BOOL_" + fullPath, mutations);

                // 7. Type confusion - null
                addMutation(seed, node, fieldName, NullNode.instance, "TYPE_CONFUSION_NULL_" + fullPath, mutations);

            } else if (originalValue.isIntegralNumber()) {
                // 8. Zero
                addMutation(seed, node, fieldName, LongNode.valueOf(0), "ZERO_" + fullPath, mutations);

                // 9. Negative
                addMutation(seed, node, fieldName, LongNode.valueOf(-1), "NEGATIVE_" + fullPath, mutations);

                // 10. Large integer
                addMutation(seed, node, fieldName, LongNode.valueOf(Integer.MAX_VALUE), "LARGE_INTEGER_" + fullPath, mutations);

                // 11. Type confusion - string
                addMutation(seed, node, fieldName, TextNode.valueOf("invalid-number"), "TYPE_CONFUSION_STR_" + fullPath, mutations);

                // 12. Type confusion - boolean
                addMutation(seed, node, fieldName, BooleanNode.valueOf(false), "TYPE_CONFUSION_BOOL_" + fullPath, mutations);

            } else if (originalValue.isFloatingPointNumber()) {
                addMutation(seed, node, fieldName, DoubleNode.valueOf(0.0), "ZERO_" + fullPath, mutations);
                addMutation(seed, node, fieldName, DoubleNode.valueOf(-1.0), "NEGATIVE_" + fullPath, mutations);
                addMutation(seed, node, fieldName, DoubleNode.valueOf(1_000_000_000.0), "LARGE_NUMBER_" + fullPath, mutations);
                addMutation(seed, node, fieldName, TextNode.valueOf("not-a-number"), "TYPE_CONFUSION_STR_" + fullPath, mutations);

            } else if (originalValue.isBoolean()) {
                addMutation(seed, node, fieldName, BooleanNode.valueOf(!originalValue.booleanValue()), "BOOLEAN_INVERSION_" + fullPath, mutations);
                addMutation(seed, node, fieldName, TextNode.valueOf("not-a-boolean"), "TYPE_CONFUSION_STR_" + fullPath, mutations);

            } else if (originalValue.isObject()) {
                // Nested object - recurse
                ObjectNode nestedCopy = originalValue.deepCopy();
                mutateObjectRecursive(nestedCopy, fullPath, depth + 1, seed, mutations);

                // Replace nested object with null
                addMutation(seed, node, fieldName, NullNode.instance, "NESTED_NULL_" + fullPath, mutations);

                // Replace nested object with empty object
                addMutation(seed, node, fieldName, mapper.createObjectNode(), "NESTED_EMPTY_" + fullPath, mutations);

            } else if (originalValue.isArray()) {
                // Array mutations
                mutateArray(node, fieldName, originalValue, fullPath, depth, seed, mutations);
            }
        }
    }

    private void mutateArray(
            ObjectNode parent,
            String fieldName,
            JsonNode arrayNode,
            String fullPath,
            int depth,
            RequestSpec seed,
            List<RequestSpec> mutations
    ) {
        if (mutations.size() >= MAX_MUTATIONS) {
            return;
        }

        ArrayNode array = (ArrayNode) arrayNode;
        int size = array.size();

        // 1. Empty array
        addMutation(seed, parent, fieldName, mapper.createArrayNode(), "ARRAY_EMPTY_" + fullPath, mutations);

        // 2. Array with one null element (if original not empty)
        if (size > 0) {
            ArrayNode oneNull = mapper.createArrayNode();
            oneNull.add(NullNode.instance);
            addMutation(seed, parent, fieldName, oneNull, "ARRAY_ONE_NULL_" + fullPath, mutations);
        }

        // 3. Remove first element (if size > 1)
        if (size > 1) {
            ArrayNode withoutFirst = mapper.createArrayNode();
            for (int i = 1; i < size; i++) {
                withoutFirst.add(array.get(i).deepCopy());
            }
            addMutation(seed, parent, fieldName, withoutFirst, "ARRAY_REMOVE_FIRST_" + fullPath, mutations);
        }

        // 4. Remove last element
        if (size > 1) {
            ArrayNode withoutLast = mapper.createArrayNode();
            for (int i = 0; i < size - 1; i++) {
                withoutLast.add(array.get(i).deepCopy());
            }
            addMutation(seed, parent, fieldName, withoutLast, "ARRAY_REMOVE_LAST_" + fullPath, mutations);
        }

        // 5. Type confusion on first element (if exists)
        if (size > 0) {
            JsonNode first = array.get(0);
            ArrayNode confused = mapper.createArrayNode();
            if (first.isTextual()) {
                confused.add(IntNode.valueOf(999));
            } else if (first.isIntegralNumber()) {
                confused.add(TextNode.valueOf("not-a-number"));
            } else if (first.isBoolean()) {
                confused.add(TextNode.valueOf("not-a-boolean"));
            } else if (first.isObject()) {
                confused.add(NullNode.instance);
            }
            if (confused.size() > 0) {
                // Copy remaining elements
                for (int i = 1; i < size; i++) {
                    confused.add(array.get(i).deepCopy());
                }
                addMutation(seed, parent, fieldName, confused, "ARRAY_TYPE_CONFUSION_" + fullPath, mutations);
            }
        }

        // 6. Duplicate array (if size <= MAX_ARRAY_SIZE/2)
        if (size > 0 && size <= MAX_ARRAY_SIZE / 2) {
            ArrayNode duplicated = mapper.createArrayNode();
            for (int i = 0; i < size * 2; i++) {
                duplicated.add(array.get(i % size).deepCopy());
            }
            addMutation(seed, parent, fieldName, duplicated, "ARRAY_DUPLICATED_" + fullPath, mutations);
        }

        // 7. Recurse into array elements that are objects (limited)
        if (depth < MAX_NESTING_DEPTH) {
            for (int i = 0; i < Math.min(size, 3) && mutations.size() < MAX_MUTATIONS; i++) {
                JsonNode element = array.get(i);
                if (element.isObject()) {
                    String elementPath = fullPath + "[" + i + "]";
                    ObjectNode elementCopy = element.deepCopy();
                    mutateObjectRecursive(elementCopy, elementPath, depth + 1, seed, mutations);
                }
            }
        }
    }

    private List<RequestSpec> generateQueryAndHeaderMutations(RequestSpec seed) {
        List<RequestSpec> mutations = new ArrayList<>();

        // Query parameter mutations
        String url = seed.getUrl();
        if (url != null && url.contains("?")) {
            String[] parts = url.split("\\?", 2);
            String basePath = parts[0];
            String query = parts[1];

            // 1. Remove each query parameter
            String[] params = query.split("&");
            for (String param : params) {
                if (mutations.size() >= MAX_MUTATIONS) break;
                String[] kv = param.split("=", 2);
                if (kv.length == 2) {
                    String newQuery = query.replace(param, "").replace("&&", "&").replaceAll("^&|&$", "");
                    String newUrl = basePath + (newQuery.isEmpty() ? "" : "?" + newQuery);
                    mutations.add(createMutatedRequest(seed, newUrl, "QUERY_MISSING_" + kv[0]));
                }
            }

            // 2. Empty value for each parameter
            for (String param : params) {
                if (mutations.size() >= MAX_MUTATIONS) break;
                String[] kv = param.split("=", 2);
                if (kv.length == 2) {
                    String newQuery = query.replace(param, kv[0] + "=");
                    String newUrl = basePath + "?" + newQuery;
                    mutations.add(createMutatedRequest(seed, newUrl, "QUERY_EMPTY_" + kv[0]));
                }
            }

            // 3. Type confusion: numeric -> string
            for (String param : params) {
                if (mutations.size() >= MAX_MUTATIONS) break;
                String[] kv = param.split("=", 2);
                if (kv.length == 2 && kv[1].matches("-?\\d+")) {
                    String newQuery = query.replace(param, kv[0] + "=" + kv[1] + "abc");
                    String newUrl = basePath + "?" + newQuery;
                    mutations.add(createMutatedRequest(seed, newUrl, "QUERY_TYPE_CONFUSION_" + kv[0]));
                }
            }
        }

        // Safe header mutations (non-security-critical)
        Map<String, String> originalHeaders = seed.getHeaders();
        if (originalHeaders != null) {
            // Content-Type variations
            if (originalHeaders.containsKey("Content-Type")) {
                String[] contentTypes = {
                    "application/json",
                    "application/xml",
                    "application/x-www-form-urlencoded",
                    "text/plain"
                };
                for (String ct : contentTypes) {
                    if (mutations.size() >= MAX_MUTATIONS) break;
                    if (!ct.equals(originalHeaders.get("Content-Type"))) {
                        Map<String, String> h = new HashMap<>(originalHeaders);
                        h.put("Content-Type", ct);
                        RequestSpec req = copyRequest(seed);
                        req.setHeaders(h);
                        req.setId(seed.getId() + "-header-ct-" + ct.replace("/", "-"));
                        req.setTestStrategy("MUTATION:HEADER_CONTENT_TYPE_" + ct.replace("/", "_"));
                        mutations.add(req);
                    }
                }
            }

            // Accept variations
            if (originalHeaders.containsKey("Accept")) {
                String[] accepts = {
                    "application/json",
                    "application/xml",
                    "*/*",
                    "text/html"
                };
                for (String a : accepts) {
                    if (mutations.size() >= MAX_MUTATIONS) break;
                    if (!a.equals(originalHeaders.get("Accept"))) {
                        Map<String, String> h = new HashMap<>(originalHeaders);
                        h.put("Accept", a);
                        RequestSpec req = copyRequest(seed);
                        req.setHeaders(h);
                        req.setId(seed.getId() + "-header-accept-" + a.replace("/", "-"));
                        req.setTestStrategy("MUTATION:HEADER_ACCEPT_" + a.replace("/", "_"));
                        mutations.add(req);
                    }
                }
            }
        }

        return mutations;
    }

    private RequestSpec createMutatedRequest(RequestSpec seed, String newUrl, String strategy) {
        RequestSpec req = copyRequest(seed);
        req.setUrl(newUrl);
        req.setId(seed.getId() + "-" + strategy.toLowerCase());
        req.setTestStrategy("MUTATION:" + strategy);
        return req;
    }

    private RequestSpec copyRequest(RequestSpec original) {
        RequestSpec copy = new RequestSpec();
        copy.setId(original.getId());
        copy.setMethod(original.getMethod());
        copy.setUrl(original.getUrl());
        copy.setHeaders(new HashMap<>(original.getHeaders()));
        copy.setBody(original.getBody());
        copy.setTestStrategy(original.getTestStrategy());
        copy.setAuthProfile(original.getAuthProfile());
        copy.setSeedId(original.getSeedId());
        return copy;
    }

    private int estimatePayloadSize(ObjectNode node) {
        try {
            return mapper.writeValueAsString(node).length();
        } catch (JsonProcessingException e) {
            return Integer.MAX_VALUE;
        }
    }

    private void addMutation(
            RequestSpec seed,
            ObjectNode original,
            String fieldName,
            JsonNode newValue,
            String strategy,
            List<RequestSpec> mutations
    ) {
        if (mutations.size() >= MAX_MUTATIONS) {
            return;
        }

        ObjectNode mutated = original.deepCopy();
        mutated.set(fieldName, newValue);

        addMutation(seed, mutated, strategy, mutations);
    }

    private void addMutation(
            RequestSpec seed,
            ObjectNode mutated,
            String strategy,
            List<RequestSpec> mutations
    ) {
        if (mutations.size() >= MAX_MUTATIONS) {
            return;
        }

        try {
            String mutatedBody = mapper.writeValueAsString(mutated);

            Map<String, String> headers =
                    seed.getHeaders() == null
                            ? new HashMap<>()
                            : new HashMap<>(seed.getHeaders());

            RequestSpec request = new RequestSpec(
                    seed.getId() + "-mutation-" + (mutations.size() + 1),
                    seed.getMethod(),
                    seed.getUrl(),
                    headers,
                    mutatedBody,
                    "MUTATION:" + strategy
            );
            request.setAuthProfile(seed.getAuthProfile());
            request.setSeedId(seed.getId());
            mutations.add(request);

        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "Could not serialize mutated JSON", e
            );
        }
    }
}