
package com.apifuzzer.execution;

import com.apifuzzer.auth.AuthProfile;
import com.apifuzzer.auth.AuthProfileManager;
import com.apifuzzer.auth.AuthProfileResolver;
import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class HttpExecutorAuthTest {

    private HttpServer server;
    private String targetUrl;

    private final AtomicReference<String> receivedAuthorization =
            new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );

        server.createContext("/api/test", exchange -> {
            receivedAuthorization.set(
                    exchange.getRequestHeaders()
                            .getFirst("Authorization")
            );

            byte[] response = "{\"status\":\"ok\"}"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set(
                    "Content-Type",
                    "application/json"
            );

            exchange.sendResponseHeaders(200, response.length);

            try (OutputStream output = exchange.getResponseBody()) {
                output.write(response);
            }
        });

        server.start();

        targetUrl = "http://127.0.0.1:"
                + server.getAddress().getPort()
                + "/api/test";
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private HttpExecutor createExecutor(
            AuthProfileManager manager
    ) {
        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);

        AuthProfileResolver resolver =
                new AuthProfileResolver(manager);

        return new HttpExecutor(
                config,
                new RequestLimiter(config),
                resolver
        );
    }

    private RequestSpec createRequest(String profileName) {
        RequestSpec request = new RequestSpec();

        request.setId("integration-test");
        request.setMethod("GET");
        request.setUrl(targetUrl);
        request.setAuthProfile(profileName);
        request.setHeaders(new HashMap<>());

        return request;
    }

    @Test
    void shouldSendBearerTokenToLocalServer() {
        AuthProfileManager manager = new AuthProfileManager();

        manager.register(
                AuthProfile.bearer(
                        "student",
                        "integration-test-token"
                )
        );

        HttpExecutor executor = createExecutor(manager);
        RequestSpec original = createRequest("student");

        Observation observation = executor.execute(original);

        assertEquals(200, observation.getStatusCode());

        assertEquals(
                "Bearer integration-test-token",
                receivedAuthorization.get()
        );

        // Authentication must not modify the original request.
        assertFalse(
                original.getHeaders().containsKey("Authorization")
        );
    }

    @Test
    void shouldSendAnonymousRequestWithoutAuthorization() {
        AuthProfileManager manager = new AuthProfileManager();

        HttpExecutor executor = createExecutor(manager);
        RequestSpec request = createRequest(null);

        Observation observation = executor.execute(request);

        assertEquals(200, observation.getStatusCode());
        assertNull(receivedAuthorization.get());
        assertFalse(
                request.getHeaders().containsKey("Authorization")
        );
    }

    @Test
    void shouldRejectUnknownProfileBeforeNetworkExecution() {
        AuthProfileManager manager = new AuthProfileManager();

        HttpExecutor executor = createExecutor(manager);
        RequestSpec request = createRequest("unknown");

        Observation observation = executor.execute(request);

        assertEquals(0, observation.getStatusCode());
        assertNotNull(observation.getErrorMessage());

        // The local server must never receive this request.
        assertNull(receivedAuthorization.get());
    }
}

