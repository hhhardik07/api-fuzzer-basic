package com.apifuzzer.report;

import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.security.ResponseSanitizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class ReportWriter {

    private final ObjectMapper objectMapper;
    private final ResponseSanitizer sanitizer;

    public ReportWriter() {
        this.objectMapper = new ObjectMapper();
        this.sanitizer = new ResponseSanitizer();
    }

    /**
     * Writes a basic findings report (backward compatible).
     */
    public void writeFindings(List<Finding> findings, Path outputPath)
            throws IOException {

        writeFindings(findings, Map.of(), Map.of(), Map.of(), outputPath);
    }

    /**
     * Writes an enriched findings report with reproducible evidence.
     *
     * @param findings           list of findings
     * @param requestsById       mutation/baseline RequestSpec keyed by request ID
     * @param observationsById   Observation keyed by request ID
     * @param baselinesBySeedId  baseline Observation keyed by seed ID
     * @param outputPath         output file path
     * @throws IOException if writing fails
     */
    public void writeFindings(
            List<Finding> findings,
            Map<String, RequestSpec> requestsById,
            Map<String, Observation> observationsById,
            Map<String, Observation> baselinesBySeedId,
            Path outputPath
    ) throws IOException {

        if (findings == null) {
            throw new IllegalArgumentException("Findings list cannot be null");
        }

        if (outputPath == null) {
            throw new IllegalArgumentException("Output path cannot be null");
        }

        ObjectNode report = objectMapper.createObjectNode();

        report.put("reportType", "API Fuzzer Security Report");
        report.put("findingCount", findings.size());
        report.put("generatedAt", java.time.Instant.now().toString());

        // --- Summary Section ---
        ObjectNode summary = objectMapper.createObjectNode();
        summary.put("totalFindings", findings.size());

        // By oracle type
        ObjectNode byType = objectMapper.createObjectNode();
        findings.stream()
                .collect(Collectors.groupingBy(Finding::getOracleType, Collectors.counting()))
                .forEach((String k, Long v) -> byType.put(k, v.toString()));
        summary.set("byOracleType", byType);

        // By severity
        ObjectNode bySeverity = objectMapper.createObjectNode();
        findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()))
                .forEach((String k, Long v) -> bySeverity.put(k, v.toString()));
        summary.set("bySeverity", bySeverity);

        // By confidence
        ObjectNode byConfidence = objectMapper.createObjectNode();
        findings.stream()
                .collect(Collectors.groupingBy(Finding::getConfidence, Collectors.counting()))
                .forEach((String k, Long v) -> byConfidence.put(k, v.toString()));
        summary.set("byConfidence", byConfidence);

        // By oracle type + severity combination
        ObjectNode byTypeSeverity = objectMapper.createObjectNode();
        findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.getOracleType() + "|" + f.getSeverity(),
                        Collectors.counting()))
                .forEach((String k, Long v) -> byTypeSeverity.put(k, v.toString()));
        summary.set("byOracleTypeAndSeverity", byTypeSeverity);

        report.set("summary", summary);

        ArrayNode findingsArray = report.putArray("findings");

        for (Finding finding : findings) {

            if (finding == null) {
                continue;
            }

            ObjectNode findingNode = findingsArray.addObject();

            findingNode.put("id", String.valueOf(finding.getId()));
            findingNode.put("requestId", String.valueOf(finding.getRequestId()));
            findingNode.put("oracleType", String.valueOf(finding.getOracleType()));

            findingNode.put(
                    "title",
                    sanitizer.sanitizeText(finding.getTitle())
            );

            findingNode.put("severity", String.valueOf(finding.getSeverity()));
            findingNode.put("confidence", String.valueOf(finding.getConfidence()));

            findingNode.put(
                    "evidence",
                    sanitizer.sanitizeBody(finding.getEvidence())
            );

            findingNode.put(
                    "recommendation",
                    sanitizer.sanitizeText(finding.getRecommendation())
            );

            findingNode.put(
                    "timestamp",
                    String.valueOf(finding.getTimestamp())
            );

            // --- Enriched reproducible context ---
            String reqId = finding.getRequestId();

            // Seed request ID from mutation's seedId (via RequestSpec)
            RequestSpec request = requestsById.get(reqId);
            if (request != null) {
                if (request.getSeedId() != null && !request.getSeedId().isBlank()) {
                    findingNode.put("seedRequestId", request.getSeedId());
                }
                findingNode.put("mutationStrategy", request.getTestStrategy());

                // Request method
                if (request.getMethod() != null) {
                    findingNode.put("method", request.getMethod());
                }

                // Sanitized target URL (strip userinfo, redact tokens)
                String sanitizedUrl = sanitizeUrl(request.getUrl());
                findingNode.put("url", sanitizedUrl);
            }

            // HTTP status from actual observation
            Observation obs = observationsById.get(reqId);
            if (obs != null) {
                findingNode.put("httpStatus", obs.getStatusCode());
                findingNode.put("durationMs", obs.getDurationMs());

                // Relevant response headers (sanitized)
                            if (obs.getResponseHeaders() != null) {
                                ObjectNode headersNode = findingNode.putObject("responseHeaders");
                                obs.getResponseHeaders().forEach((key, values) -> {
                                    if (!key.equalsIgnoreCase("authorization")
                                            && !key.equalsIgnoreCase("cookie")
                                            && !key.equalsIgnoreCase("set-cookie")
                                            && !key.equalsIgnoreCase("proxy-authorization")
                                            && !key.equalsIgnoreCase("x-api-key")) {
                                        ArrayNode array = headersNode.putArray(key);
                                        for (String v : values) {
                                            array.add(v);
                                        }
                                    }
                                });
                            }
            }

            // Baseline comparison
            if (request != null && request.getSeedId() != null) {
                Observation baseline = baselinesBySeedId.get(request.getSeedId());
                if (baseline != null) {
                    findingNode.put("baselineStatus", baseline.getStatusCode());
                    findingNode.put("baselineContentType", getContentType(baseline));
                    findingNode.put("actualContentType", getContentType(obs));
                }
            }
        }

        Path parent = outputPath.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        objectMapper.writerWithDefaultPrettyPrinter()
                .writeValue(outputPath.toFile(), report);
    }

    private String sanitizeUrl(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(url);
            // Strip userinfo (already validated as disallowed, but defensive)
            if (uri.getUserInfo() != null) {
                URI cleaned = new URI(
                        uri.getScheme(),
                        null, // no userinfo
                        uri.getHost(),
                        uri.getPort(),
                        uri.getPath(),
                        uri.getQuery(),
                        uri.getFragment()
                );
                url = cleaned.toString();
            }
            // Sanitize any bearer/basic tokens in URL (unlikely but defensive)
            return sanitizer.sanitizeText(url);
        } catch (URISyntaxException e) {
            return sanitizer.sanitizeText(url);
        }
    }

    private String getContentType(Observation observation) {
        if (observation == null || observation.getResponseHeaders() == null) {
            return "";
        }
        return observation.getResponseHeaders()
                .entrySet()
                .stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase("content-type"))
                .flatMap(entry -> entry.getValue().stream())
                .findFirst()
                .orElse("");
    }
}