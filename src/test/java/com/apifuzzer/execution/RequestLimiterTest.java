package com.apifuzzer.execution;

import com.apifuzzer.config.FuzzerConfig;
import org.junit.jupiter.api.Test;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.*;

class RequestLimiterTest {

    @Test
    void shouldEnforceSessionLimit() {

        FuzzerConfig config = new FuzzerConfig();
        config.setRequestsPerSecond(10);
        config.setMaxRequestsPerSession(2);

        RequestLimiter limiter = new RequestLimiter(config);

        assertTrue(limiter.acquire());
        assertTrue(limiter.acquire());

        // Third request must be rejected.
        assertFalse(limiter.acquire());

        assertEquals(2, limiter.getTotalRequests());
        assertEquals(0, limiter.getRemainingRequests());
    }

    @Test
    void shouldEnforceRequestRate() {

        FuzzerConfig config = new FuzzerConfig();
        config.setRequestsPerSecond(2);
        config.setMaxRequestsPerSession(5);

        RequestLimiter limiter = new RequestLimiter(config);

        long start = System.nanoTime();

        assertTrue(limiter.acquire());
        assertTrue(limiter.acquire());

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        // At 2 requests per second, the second request
        // should wait approximately 500 milliseconds.
        assertTrue(
                elapsedMs >= 400,
                "Requests were sent too close together: "
                        + elapsedMs + " ms"
        );
    }

    @Test
    void shouldTrackRemainingRequests() {

        FuzzerConfig config = new FuzzerConfig();
        config.setRequestsPerSecond(10);
        config.setMaxRequestsPerSession(5);

        RequestLimiter limiter = new RequestLimiter(config);

        assertEquals(5, limiter.getRemainingRequests());

        assertTrue(limiter.acquire());

        assertEquals(4, limiter.getRemainingRequests());
    }
    
    @Test
void shouldRejectRequestWhenAlreadyCancelled() {
    RequestLimiter limiter = new RequestLimiter(new FuzzerConfig());
    AtomicBoolean cancellationToken = new AtomicBoolean(true);

    assertFalse(limiter.acquire(cancellationToken));
}

@Test
void shouldStopWaitingPromptlyWhenCancelled() throws Exception {
    RequestLimiter limiter = new RequestLimiter(new FuzzerConfig());

    // Reserve the first request slot. The next request must wait.
    assertTrue(limiter.acquire());

    AtomicBoolean cancellationToken = new AtomicBoolean(false);
    CountDownLatch started = new CountDownLatch(1);

    ExecutorService executor = Executors.newSingleThreadExecutor();

    try {
        Future<Boolean> result = executor.submit(() -> {
            started.countDown();
            return limiter.acquire(cancellationToken);
        });

        assertTrue(started.await(1, TimeUnit.SECONDS));

        // Give the worker time to enter the rate-limit wait.
        Thread.sleep(50);

        cancellationToken.set(true);

        // Cancellation should interrupt the wait promptly.
        assertFalse(result.get(1, TimeUnit.SECONDS));
    } finally {
        executor.shutdownNow();
    }
}
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
