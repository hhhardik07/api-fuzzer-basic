
package com.apifuzzer.model;

import com.apifuzzer.security.ResponseSanitizer;

import java.time.Instant;
import java.util.UUID;

public class Finding {

    private static final ResponseSanitizer SANITIZER =
            new ResponseSanitizer();

    private final String id;
    private final String requestId;
    private final String oracleType;
    private final String title;
    private final String severity;
    private final String confidence;
    private final String evidence;
    private final String recommendation;
    private final Instant timestamp;

    public Finding(
            String requestId,
            String oracleType,
            String title,
            String severity,
            String confidence,
            String evidence,
            String recommendation
    ) {
        this.id = UUID.randomUUID().toString();
        this.requestId = requestId;
        this.oracleType = oracleType;
        this.title = SANITIZER.sanitizeText(title);
        this.severity = severity;
        this.confidence = confidence;
        this.evidence = SANITIZER.sanitizeBody(evidence);
        this.recommendation = SANITIZER.sanitizeText(recommendation);
        this.timestamp = Instant.now();
    }

    public String getId() {
        return id;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getOracleType() {
        return oracleType;
    }

    public String getTitle() {
        return title;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public Instant getTimestamp() {
        return timestamp;
    }
}

