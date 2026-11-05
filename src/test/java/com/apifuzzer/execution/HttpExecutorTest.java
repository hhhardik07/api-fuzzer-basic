package com.apifuzzer.execution;
import com.apifuzzer.security.TargetScope;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.config.FuzzerConfig;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.util.Set;
import java.net.InetSocketAddress;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class HttpExecutorTest {

    private static HttpServer server;
    private static final int PORT = 8765;

    @BeforeAll
    static void startServer() throws Exception {

        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", PORT), 0
        );

        server.createContext("/hello", exchange -> {

            byte[] response = "Hello from mock API".getBytes();

            exchange.getResponseHeaders().add(
                    "Content-Type", "text/plain"
            );

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldExecuteGetRequest() {

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);
        HttpExecutor executor = new HttpExecutor(config);

        RequestSpec request = new RequestSpec(
                "test-001",
                "GET",
                "http://127.0.0.1:" + PORT + "/hello",
                new HashMap<>(),
                null,
                "BASELINE"
        );

        Observation result = executor.execute(request);

        assertEquals(200, result.getStatusCode());
        assertEquals("Hello from mock API", result.getResponseBody());
        assertTrue(result.isSuccessful());
        assertEquals("test-001", result.getRequestId());
        assertNull(result.getErrorMessage());
    }

    @Test
    void shouldRejectExternalTarget() {

        HttpExecutor executor = new HttpExecutor();

        RequestSpec request = new RequestSpec(
                "test-002",
                "GET",
                "https://example.com",
                new HashMap<>(),
                null,
                "BASELINE"
        );

        Observation result = executor.execute(request);

        assertEquals(0, result.getStatusCode());
        assertNotNull(result.getErrorMessage());
        assertTrue(result.getErrorMessage().contains("allowlist"));
    }
    
    @Test
void shouldRejectRequestOutsideConfiguredPathScope() {

    FuzzerConfig config = new FuzzerConfig();
    config.setAllowNonPublicTargets(true);
    config.setAllowedHosts(Set.of("localhost"));
    config.setAllowedMethods(Set.of("GET"));

    TargetScope scope = new TargetScope(
            Set.of("localhost"),
            Set.of("GET"),
            Set.of("/approved")
    );

    HttpExecutor executor = new HttpExecutor(
            config,
            null,
            null,
            scope
    );

    RequestSpec request = new RequestSpec(
            "scope-test",
            "GET",
            "http://localhost:8080/admin/users",
            new HashMap<>(),
            null,
            "BASELINE"
    );

    Observation observation = executor.execute(request);

    assertNotNull(observation.getErrorMessage());
    assertTrue(
            observation.getErrorMessage().toLowerCase().contains("scope")
                    || observation.getErrorMessage().toLowerCase().contains("path")
    );
}
    
    
    
}
