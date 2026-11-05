package com.apifuzzer.oracle;

import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class OracleEngine {

    private final ObjectMapper mapper = new ObjectMapper();

    private static final Pattern STACK_TRACE = Pattern.compile(
            "(?i)(at\\s+[\\w.$]+\\([\\w.$]+\\.java:\\d+\\))"
                    + "|(Traceback \\(most recent call last\\))"
                    + "|(Exception in thread)"
                    + "|(stack trace)"
    );

    private static final Pattern DATABASE_ERROR = Pattern.compile(
            "(?i)(SQL syntax.*error)"
                    + "|(SQLException)"
                    + "|(SQLSTATE\\[)"
                    + "|(ORA-\\d{5})"
                    + "|(PostgreSQL.*ERROR)"
                    + "|(mysql_fetch)"
                    + "|(SQLiteException)"
                    + "|(constraint violation)"
                    + "|(duplicate key)"
                    + "|(foreign key constraint)"
    );

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password",
            "password_hash",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "api_secret",
            "session_secret",
            "secret",
            "api_key",
            "jwt",
            "authorization"
    );

    // Track findings for deduplication
    private final Map<String, Finding> findingCache = new HashMap<>();

    public List<Finding> evaluate(
            RequestSpec request,
            Observation baseline,
            Observation actual
    ) {

        if (request == null || actual == null) {
            throw new IllegalArgumentException(
                    "Request and actual observation are required"
            );
        }

        List<Finding> findings = new ArrayList<>();

        if (actual.getErrorMessage() != null) {
            return findings;
        }

        checkServerError(request, baseline, actual, findings);
        checkStackTrace(request, actual, findings);
        checkDatabaseError(request, actual, findings);
        checkSensitiveFields(request, actual, findings);
        checkResponseAnomaly(request, baseline, actual, findings);

        // Deduplicate findings
        return deduplicateFindings(findings);
    }

    private void checkServerError(
            RequestSpec request,
            Observation baseline,
            Observation actual,
            List<Finding> findings
    ) {

        if (actual.getStatusCode() >= 500) {
            String evidence = "Mutated request returned HTTP " + actual.getStatusCode();

            if (baseline != null && baseline.getStatusCode() < 500) {
                evidence += ". Baseline was " + baseline.getStatusCode() + ".";
                findings.add(new Finding(
                        request.getId(),
                        "STATUS_ORACLE",
                        "New server error introduced by mutation",
                        "LOW",
                        "LOW",
                        evidence,
                        "Review server-side error handling and reproduce with the same test input."
                ));
            } else if (baseline == null) {
                evidence += ". No baseline available for comparison.";
                findings.add(new Finding(
                        request.getId(),
                        "STATUS_ORACLE",
                        "Server error on mutated request",
                        "LOW",
                        "LOW",
                        evidence,
                        "This may be an existing server issue. Verify with the original request."
                ));
            } else {
                // Both baseline and actual are 5xx - check for new error details
                String actualBody = actual.getResponseBody() != null ? actual.getResponseBody() : "";
                String baselineBody = baseline.getResponseBody() != null ? baseline.getResponseBody() : "";
                if (!actualBody.equals(baselineBody)) {
                    evidence += " with changed error response.";
                    findings.add(new Finding(
                            request.getId(),
                            "STATUS_ORACLE",
                            "Server error with changed error details",
                            "LOW",
                            "LOW",
                            evidence,
                            "Compare error responses to identify new information disclosure."
                    ));
                }
            }
        }
    }

    private void checkStackTrace(
            RequestSpec request,
            Observation actual,
            List<Finding> findings
    ) {

        String body = actual.getResponseBody();

        if (body == null || !STACK_TRACE.matcher(body).find()) {
            return;
        }

        // Additional credibility checks
        boolean credible = isCredibleStackTrace(body);
        String confidence = credible ? "MEDIUM" : "LOW";

        findings.add(new Finding(
                request.getId(),
                "ERROR_DISCLOSURE_ORACLE",
                "Possible stack trace disclosure",
                "MEDIUM",
                confidence,
                "Response contains a recognizable stack trace signature: " + extractTraceSnippet(body),
                "Disable detailed exception output in production responses and log diagnostics server-side."
        ));
    }

    private boolean isCredibleStackTrace(String body) {
        // Look for multiple stack trace frames (at least 2 "at ..." lines)
        int frameCount = 0;
        int idx = 0;
        while ((idx = body.indexOf("at ", idx)) != -1) {
            frameCount++;
            idx += 3;
            if (frameCount >= 2) return true;
        }
        // Look for "Caused by:" pattern
        if (body.toLowerCase(Locale.ROOT).contains("caused by:")) return true;
        // Look for Java exception class names
        if (body.matches("(?s).*\\b(NullPointerException|IllegalArgumentException|IllegalStateException|RuntimeException|IOException|SQLException)\\b.*")) return true;
        return false;
    }

    private String extractTraceSnippet(String body) {
        int idx = body.toLowerCase(Locale.ROOT).indexOf("at ");
        if (idx == -1) idx = body.toLowerCase(Locale.ROOT).indexOf("exception");
        if (idx == -1) return body.substring(0, Math.min(200, body.length()));
        return body.substring(idx, Math.min(idx + 300, body.length()));
    }

    private void checkDatabaseError(
            RequestSpec request,
            Observation actual,
            List<Finding> findings
    ) {

        String body = actual.getResponseBody();

        if (body == null || !DATABASE_ERROR.matcher(body).find()) {
            return;
        }

        // Filter out generic SQL that might be in documentation/examples
        if (isLikelyRealDatabaseError(body)) {
            findings.add(new Finding(
                    request.getId(),
                    "DATABASE_ERROR_ORACLE",
                    "Possible database error disclosure",
                    "MEDIUM",
                    "MEDIUM",
                    "Response contains a recognizable database error signature: " + extractErrorSnippet(body),
                    "Review input validation, parameterized queries, and production error handling."
            ));
        }
    }

    private boolean isLikelyRealDatabaseError(String body) {
        String lower = body.toLowerCase(Locale.ROOT);

        // Exclude common false positives
        if (lower.contains("example") || lower.contains("sample") || lower.contains("tutorial")) return false;
        if (lower.contains("documentation") || lower.contains("test") || lower.contains("mock")) return false;

        // Must have specific error details
        return lower.matches("(?s).*(error|exception|violation|constraint|syntax|duplicate|foreign key).*")
                && (lower.contains("sql") || lower.contains("database") || lower.contains("table")
                        || lower.contains("column") || lower.contains("constraint"));
    }

    private String extractErrorSnippet(String body) {
        int idx = body.toLowerCase(Locale.ROOT).indexOf("error");
        if (idx == -1) idx = body.toLowerCase(Locale.ROOT).indexOf("exception");
        if (idx == -1) idx = body.toLowerCase(Locale.ROOT).indexOf("sql");
        if (idx == -1) return body.substring(0, Math.min(200, body.length()));
        return body.substring(Math.max(0, idx - 50), Math.min(idx + 200, body.length()));
    }

    private void checkSensitiveFields(
            RequestSpec request,
            Observation actual,
            List<Finding> findings
    ) {

        String body = actual.getResponseBody();

        if (body == null || body.isBlank()) {
            return;
        }

        try {
            JsonNode root = mapper.readTree(body);

            List<String> exposedKeys = new ArrayList<>();

            findSensitiveKeysWithValues(root, exposedKeys);

            if (!exposedKeys.isEmpty()) {
                findings.add(new Finding(
                        request.getId(),
                        "INFORMATION_DISCLOSURE_ORACLE",
                        "Potentially sensitive response fields with values",
                        "MEDIUM",
                        "LOW",
                        "Response contains sensitive-looking fields with non-empty values: " + String.join(", ", exposedKeys)
                                + ". Field names alone do not prove that their values are exposed improperly.",
                        "Review the response against the endpoint's authorized data contract and ensure secrets are never returned."
                ));
            }

        } catch (Exception ignored) {
            // Non-JSON responses are not evaluated by this detector.
        }
    }

    private void findSensitiveKeysWithValues(
            JsonNode node,
            List<String> exposedKeys
    ) {

        if (node == null) {
            return;
        }

        if (node.isObject()) {

            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();

            while (fields.hasNext()) {

                Map.Entry<String, JsonNode> field = fields.next();

                String key = field.getKey().toLowerCase(Locale.ROOT);

                if (SENSITIVE_KEYS.contains(key)
                        && !field.getValue().isNull()
                        && !field.getValue().asText().isBlank()) {

                    // Only flag if value looks like a real secret (not placeholder)
                    String value = field.getValue().asText();
                    if (!isPlaceholderValue(value)) {
                        if (!exposedKeys.contains(field.getKey())) {
                            exposedKeys.add(field.getKey());
                        }
                    }
                }

                findSensitiveKeysWithValues(field.getValue(), exposedKeys);
            }

        } else if (node.isArray()) {

            for (JsonNode element : node) {
                findSensitiveKeysWithValues(element, exposedKeys);
            }
        }
    }

    private boolean isPlaceholderValue(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.equals("example")
                || lower.equals("test")
                || lower.equals("placeholder")
                || lower.equals("dummy")
                || lower.equals("redacted")
                || lower.equals("<redacted>")
                || lower.startsWith("xxx")
                || lower.startsWith("***")
                || value.length() < 4; // Too short to be a real secret
    }

    private void checkResponseAnomaly(
            RequestSpec request,
            Observation baseline,
            Observation actual,
            List<Finding> findings
    ) {

        if (baseline == null) {
            return;
        }

        boolean statusChanged = baseline.getStatusCode() != actual.getStatusCode();

        String baselineType = getContentType(baseline);
        String actualType = getContentType(actual);

        boolean contentTypeChanged = !baselineType.equals(actualType);

        if (!statusChanged && !contentTypeChanged) {
            return;
        }

        String evidence = "Baseline status: " + baseline.getStatusCode()
                + ", mutated status: " + actual.getStatusCode()
                + ". Baseline content type: " + baselineType
                + ", mutated content type: " + actualType + ".";

        String title = "Response behavior changed after mutation";
        String severity = "INFO";
        String confidence = "LOW";

        // If status changed to error range, increase severity
        if (actual.getStatusCode() >= 400 && baseline.getStatusCode() < 400) {
            severity = "LOW";
            confidence = "LOW";
            title = "Mutation caused error response";
        }

        findings.add(new Finding(
                request.getId(),
                "RESPONSE_ANOMALY_ORACLE",
                title,
                severity,
                confidence,
                evidence,
                "Compare the baseline and mutated responses. Investigate whether the behavior change is expected."
        ));
    }

    private String getContentType(Observation observation) {

        if (observation.getResponseHeaders() == null) {
            return "";
        }

        return observation.getResponseHeaders()
                .entrySet()
                .stream()
                .filter(entry ->
                        entry.getKey().equalsIgnoreCase("content-type"))
                .flatMap(entry -> entry.getValue().stream())
                .findFirst()
                .orElse("");
    }

    private List<Finding> deduplicateFindings(List<Finding> findings) {
        List<Finding> deduplicated = new ArrayList<>();

        for (Finding finding : findings) {
            String key = finding.getOracleType() + "|" + finding.getRequestId() + "|"
                    + finding.getTitle().toLowerCase(Locale.ROOT);

            Finding existing = findingCache.get(key);
            if (existing == null) {
                findingCache.put(key, finding);
                deduplicated.add(finding);
            }
        }

        return deduplicated;
    }
}