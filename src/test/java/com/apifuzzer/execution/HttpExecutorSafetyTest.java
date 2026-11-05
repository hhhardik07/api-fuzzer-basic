
package com.apifuzzer.execution;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.security.TargetScope;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class HttpExecutorSafetyTest {

    private HttpServer server;
    private int port;

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );

        port = server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private RequestSpec createGetRequest(String id, String path) {
        return new RequestSpec(
                id,
                "GET",
                "http://127.0.0.1:" + port + path,
                new HashMap<>(),
                null,
                "BASELINE"
        );
    }

    private FuzzerConfig createConfig() {
    FuzzerConfig config = new FuzzerConfig();

    config.setAllowedHosts(Set.of("127.0.0.1"));
    config.setAllowedMethods(Set.of("GET"));

    // Explicitly permit loopback for local integration tests only.
    config.setAllowNonPublicTargets(true);

    return config;
}

    @Test
    void shouldRejectOutOfScopeRequestBeforeNetworkExecution() {

        AtomicInteger requestCount = new AtomicInteger(0);

        server.createContext("/", exchange -> {
            requestCount.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });

        TargetScope scope = new TargetScope(
                Set.of("127.0.0.1"),
                Set.of("GET"),
                Set.of("/approved")
        );

        HttpExecutor executor = new HttpExecutor(
                createConfig(),
                null,
                null,
                scope
        );

        Observation observation = executor.execute(
                createGetRequest("scope-test", "/outside")
        );

        assertNotNull(observation.getErrorMessage());
        assertTrue(
                observation.getErrorMessage().toLowerCase().contains("scope")
        );

        assertEquals(
                0,
                requestCount.get(),
                "An out-of-scope request must never reach the server"
        );
    }

    @Test
    void shouldTruncateResponseAtConfiguredSizeLimit() {

        byte[] responseBytes = "A".repeat(2048)
                .getBytes(StandardCharsets.UTF_8);

        server.createContext("/large", exchange -> {
            exchange.sendResponseHeaders(200, responseBytes.length);

            try (var output = exchange.getResponseBody()) {
                output.write(responseBytes);
            }
        });

        FuzzerConfig config = createConfig();
        config.setMaxResponseSizeBytes(1024);

        TargetScope scope = new TargetScope(
                Set.of("127.0.0.1"),
                Set.of("GET"),
                Set.of("/large")
        );

        HttpExecutor executor = new HttpExecutor(
                config,
                null,
                null,
                scope
        );

        Observation observation = executor.execute(
                createGetRequest("large-response-test", "/large")
        );

        assertNull(observation.getErrorMessage());
        assertEquals(200, observation.getStatusCode());

        assertEquals(
                1024,
                observation.getResponseBody().length(),
                "Response body should be truncated to the configured limit"
        );
    }
}

