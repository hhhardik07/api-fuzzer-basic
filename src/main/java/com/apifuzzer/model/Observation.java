package com.apifuzzer.model;

import java.time.Instant;
import java.util.Map;

public class Observation {

    private String requestId;
    private int statusCode;
    private String responseBody;
    private Map<String, java.util.List<String>> responseHeaders;
    private long durationMs;
    private boolean successful;
    private String errorMessage;
    private Instant timestamp;

    public Observation() {
        this.timestamp = Instant.now();
    }

    public Observation(
            String requestId,
            int statusCode,
            String responseBody,
            Map<String, java.util.List<String>> responseHeaders,
            long durationMs
    ) {
        this.requestId = requestId;
        this.statusCode = statusCode;
        this.responseBody = responseBody;
        this.responseHeaders = responseHeaders;
        this.durationMs = durationMs;
        this.successful = statusCode >= 200 && statusCode < 400;
        this.timestamp = Instant.now();
    }

    public String getRequestId() {
        return requestId;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public Map<String, java.util.List<String>> getResponseHeaders() {
        return responseHeaders;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
