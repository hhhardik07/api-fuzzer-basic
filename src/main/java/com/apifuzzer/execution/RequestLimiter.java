
package com.apifuzzer.execution;

import com.apifuzzer.config.FuzzerConfig;

import java.util.concurrent.atomic.AtomicInteger;

public class RequestLimiter {

    private final int maxRequestsPerSecond;
    private final int maxRequestsPerSession;

    private final AtomicInteger totalRequests =
            new AtomicInteger(0);

    private long nextAllowedRequestTime = 0;

    public RequestLimiter(FuzzerConfig config) {

        if (config == null) {
            throw new IllegalArgumentException(
                    "FuzzerConfig cannot be null"
            );
        }

        this.maxRequestsPerSecond =
                config.getRequestsPerSecond();

        this.maxRequestsPerSession =
                config.getMaxRequestsPerSession();

        if (maxRequestsPerSecond <= 0) {
            throw new IllegalArgumentException(
                    "Requests per second must be positive"
            );
        }

        if (maxRequestsPerSession <= 0) {
            throw new IllegalArgumentException(
                    "Maximum session requests must be positive"
            );
        }
    }

    /**
     * Backward-compatible acquisition method.
     */
    public boolean acquire() {
        return acquire(null);
    }

    /**
     * Acquires a request slot while observing an optional
     * cancellation token.
     *
     * Returns false when the session limit is reached,
     * cancellation is requested, or the thread is interrupted.
     */
    public boolean acquire(
            java.util.concurrent.atomic.AtomicBoolean cancellationToken
    ) {

        while (true) {

            if (Thread.currentThread().isInterrupted()) {
                return false;
            }

            if (cancellationToken != null
                    && cancellationToken.get()) {
                return false;
            }

            long waitMillis;

            synchronized (this) {

                if (totalRequests.get() >= maxRequestsPerSession) {
                    return false;
                }

                long now = System.currentTimeMillis();

                waitMillis = Math.max(
                        0,
                        nextAllowedRequestTime - now
                );

                if (waitMillis == 0) {

                    if (cancellationToken != null
                            && cancellationToken.get()) {
                        return false;
                    }

                    if (totalRequests.get() >= maxRequestsPerSession) {
                        return false;
                    }

                    totalRequests.incrementAndGet();

                    nextAllowedRequestTime =
                            System.currentTimeMillis()
                                    + Math.max(
                                            1,
                                            1000L / maxRequestsPerSecond
                                    );

                    return true;
                }
            }

            try {
                Thread.sleep(Math.min(waitMillis, 50));

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    public int getTotalRequests() {
        return totalRequests.get();
    }

    public int getRemainingRequests() {
        return Math.max(
                0,
                maxRequestsPerSession - totalRequests.get()
        );
    }
}

