package com.apifuzzer.config;

import java.nio.file.Path;
import java.util.Set;

public class FuzzerConfig {

   private boolean allowNonPublicTargets = false;

    private Path reportOutputPath = null;

    private Set<String> allowedHosts = Set.of(
            "localhost",
            "127.0.0.1",
            "::1"
    );

    private Set<String> allowedMethods = Set.of(
            "GET", "POST", "PUT", "PATCH", "DELETE"
    );

    private int requestTimeoutSeconds = 5;

    private int maxResponseSizeBytes = 1024 * 1024;

    private int requestsPerSecond = 2;

    private int maxRequestsPerSession = 100;

    public Set<String> getAllowedHosts() {
        return allowedHosts;
    }

    public void setAllowedHosts(Set<String> allowedHosts) {
        this.allowedHosts = Set.copyOf(allowedHosts);
    }

    public Set<String> getAllowedMethods() {
        return allowedMethods;
    }

    public void setAllowedMethods(Set<String> allowedMethods) {
        this.allowedMethods = Set.copyOf(allowedMethods);
    }

    public int getRequestTimeoutSeconds() {
        return requestTimeoutSeconds;
    }

    public void setRequestTimeoutSeconds(int seconds) {
        if (seconds < 1 || seconds > 60) {
            throw new IllegalArgumentException(
                    "Timeout must be between 1 and 60 seconds"
            );
        }
        this.requestTimeoutSeconds = seconds;
    }

    public int getMaxResponseSizeBytes() {
        return maxResponseSizeBytes;
    }

    public void setMaxResponseSizeBytes(int bytes) {
        if (bytes < 1024 || bytes > 10 * 1024 * 1024) {
            throw new IllegalArgumentException(
                    "Response limit must be between 1 KB and 10 MB"
            );
        }
        this.maxResponseSizeBytes = bytes;
    }

    public int getRequestsPerSecond() {
        return requestsPerSecond;
    }

    public void setRequestsPerSecond(int rate) {
        if (rate < 1 || rate > 10) {
            throw new IllegalArgumentException(
                    "Request rate must be between 1 and 10 per second"
            );
        }
        this.requestsPerSecond = rate;
    }

    public int getMaxRequestsPerSession() {
        return maxRequestsPerSession;
    }

    public void setMaxRequestsPerSession(int maximum) {
        if (maximum < 1 || maximum > 10000) {
            throw new IllegalArgumentException(
                    "Session request limit must be between 1 and 10000"
            );
        }
        this.maxRequestsPerSession = maximum;
    }
    
    public boolean isAllowNonPublicTargets() {
    return allowNonPublicTargets;
}

public void setAllowNonPublicTargets(boolean allow) {
    this.allowNonPublicTargets = allow;
}

    /**
     * Optional path where a JSON findings report is written when a fuzzing
     * session completes. When null, no report file is produced automatically.
     */
    public Path getReportOutputPath() {
        return reportOutputPath;
    }

    public void setReportOutputPath(Path reportOutputPath) {
        this.reportOutputPath = reportOutputPath;
    }
}
