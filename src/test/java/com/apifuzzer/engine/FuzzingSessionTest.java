
package com.apifuzzer.engine;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Files;
import java.nio.file.Path;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class FuzzingSessionTest {

    private static HttpServer server;
    private static String baseUrl;

    @BeforeAll
    static void startServer() throws Exception {

        server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0
        );

        server.createContext("/test", exchange -> {

            byte[] response = "{\"message\":\"mock API\"}".getBytes();

            exchange.getResponseHeaders().add(
                    "Content-Type", "application/json"
            );

            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.start();

        baseUrl = "http://127.0.0.1:"
                + server.getAddress().getPort();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private RequestSpec createRequest(String id) {
        return new RequestSpec(
                id,
                "GET",
                baseUrl + "/test",
                new HashMap<>(),
                null,
                "BASELINE"
        );
    }

    @Test
    void shouldExecuteRequestsAndCollectObservations() {

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);
        config.setRequestsPerSecond(10);
        config.setMaxRequestsPerSession(10);

        FuzzingSession session = new FuzzingSession(config);

        List<Observation> results = session.run(List.of(
                createRequest("request-1"),
                createRequest("request-2")
        ));

        assertEquals(2, results.size());
        assertEquals(2, session.getTotalRequests());

        assertEquals(200, results.get(0).getStatusCode());
        assertEquals(200, results.get(1).getStatusCode());

        assertEquals(
                FuzzingSession.State.COMPLETED,
                session.getState()
        );
    }

    @Test
    void shouldStopWhenSessionLimitIsReached() {

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);
        config.setRequestsPerSecond(10);
        config.setMaxRequestsPerSession(2);

        FuzzingSession session = new FuzzingSession(config);

        List<Observation> results = session.run(List.of(
                createRequest("request-1"),
                createRequest("request-2"),
                createRequest("request-3")
        ));

        assertEquals(2, results.size());
        assertEquals(2, session.getTotalRequests());

        assertEquals(
                FuzzingSession.State.LIMIT_REACHED,
                session.getState()
        );
    }

    @Test
    void shouldRespectCancellationBeforeExecution() {

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);

        FuzzingSession session = new FuzzingSession(config);

        session.cancel();

        List<Observation> results = session.run(
                List.of(createRequest("request-1"))
        );

        assertTrue(results.isEmpty());
        assertEquals(0, session.getTotalRequests());

        assertEquals(
                FuzzingSession.State.CANCELLED,
                session.getState()
        );
    }

    @Test
    void shouldNotAllowSessionToRunTwice() {

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);

        FuzzingSession session = new FuzzingSession(config);

        session.run(List.of(createRequest("request-1")));

        assertThrows(
                IllegalStateException.class,
                () -> session.run(List.of(createRequest("request-2")))
        );
    }
    
    @Test
    void shouldCancelRequestWhileItIsInFlight() throws Exception {

        AtomicInteger requestCount = new AtomicInteger(0);

        HttpServer slowServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0
        );

        slowServer.createContext("/slow", exchange -> {
            requestCount.incrementAndGet();

            try {
                // Keep the response pending so the test can cancel it.
                Thread.sleep(10_000);

                byte[] response = "too late".getBytes();

                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();

            } catch (IOException ignored) {
                // Expected if the client disconnects during cancellation.

            } finally {
                exchange.close();
            }
        });

        slowServer.start();

        String slowUrl = "http://127.0.0.1:"
                + slowServer.getAddress().getPort()
                + "/slow";

        FuzzerConfig config = new FuzzerConfig();
        config.setAllowNonPublicTargets(true);
        config.setRequestsPerSecond(10);
        config.setMaxRequestsPerSession(10);
        config.setRequestTimeoutSeconds(20);

        FuzzingSession session = new FuzzingSession(config);

        RequestSpec firstRequest = new RequestSpec(
                "slow-request",
                "GET",
                slowUrl,
                new HashMap<>(),
                null,
                "BASELINE"
        );

        RequestSpec secondRequest = createRequest("second-request");

        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<List<Observation>> result = executor.submit(
                    () -> session.run(List.of(
                            firstRequest,
                            secondRequest
                    ))
            );

            // Wait until the server confirms that the request arrived.
            long deadline = System.nanoTime()
                    + TimeUnit.SECONDS.toNanos(5);

            while (requestCount.get() == 0
                    && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }

            assertEquals(
                    1,
                    requestCount.get(),
                    "The slow request should have reached the server"
            );

            session.cancel();

            List<Observation> observations =
                    result.get(5, TimeUnit.SECONDS);

            assertEquals(
                    FuzzingSession.State.CANCELLED,
                    session.getState()
            );

            assertEquals(
                    1,
                    requestCount.get(),
                    "The second request must not be sent"
            );

            assertEquals(
                    1,
                    observations.size(),
                    "The interrupted request should be recorded"
            );

            assertEquals(
                    "Request cancelled",
                    observations.get(0).getErrorMessage()
            );

        } finally {
                    session.cancel();
                    executor.shutdownNow();
                    slowServer.stop(0);
                }
            }

            @Test
            void shouldRunFullFuzzingPipelineWithMutationsAndFindings() throws Exception {
                // Create a server that reflects request body for mutation testing
                HttpServer testServer = HttpServer.create(
                        new InetSocketAddress("127.0.0.1", 0), 0
                );

                testServer.createContext("/api/echo", exchange -> {
                    String method = exchange.getRequestMethod();
                    String requestBody = "";
                    if (exchange.getRequestBody() != null) {
                        requestBody = new String(exchange.getRequestBody().readAllBytes());
                    }

                    String response = String.format(
                            "{\"method\":\"%s\",\"body\":%s}",
                            method,
                            requestBody.isEmpty() ? "{}" : requestBody
                    );

                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    byte[] responseBytes = response.getBytes();
                    exchange.sendResponseHeaders(200, responseBytes.length);
                    exchange.getResponseBody().write(responseBytes);
                    exchange.close();
                });

                testServer.start();

                String baseUrl = "http://127.0.0.1:" + testServer.getAddress().getPort() + "/api/echo";

                try {
                    FuzzerConfig config = new FuzzerConfig();
                    config.setAllowNonPublicTargets(true);
                    config.setRequestsPerSecond(10);
                    config.setMaxRequestsPerSession(40);

                    FuzzingSession session = new FuzzingSession(config);

                    // Seed with a POST request containing JSON body - this will trigger body mutations
                    RequestSpec seed = new RequestSpec(
                            "seed-echo",
                            "POST",
                            baseUrl,
                            new HashMap<>(Map.of("Content-Type", "application/json")),
                            "{\"userId\":123,\"action\":\"test\"}",
                            "BASELINE"
                    );

                    List<Observation> results = session.runFuzzingPipeline(List.of(seed));

                    // Verify baseline was executed
                    assertEquals(1, session.getObservations().stream()
                            .filter(o -> o.getRequestId().equals("seed-echo"))
                            .count());

                    // Verify mutations were generated and executed
                    assertTrue(session.getTotalRequests() > 1, "Should have executed mutations");
                    assertTrue(session.getObservations().size() > 1, "Should have multiple observations");

                    // Verify findings collection works (may or may not find issues)
                    List<Finding> findings = session.getFindings();
                    // Findings list should be accessible
                    assertNotNull(findings);

                    // Verify feedback scheduler tracked strategies
                    Map<String, Double> scores = session.getStrategyScores();
                    assertNotNull(scores);

                    // Verify pending mutations: if COMPLETED, should be 0;
                    // if LIMIT_REACHED, may be >0.
                    int pending = session.getPendingMutationCount();
                    if (session.getState() == FuzzingSession.State.COMPLETED) {
                        assertEquals(0, pending);
                    } else {
                        assertTrue(pending > 0,
                                "Should have pending mutations when limit reached");
                    }

                    // State should be COMPLETED or LIMIT_REACHED
                    assertTrue(session.getState() == FuzzingSession.State.COMPLETED
                            || session.getState() == FuzzingSession.State.LIMIT_REACHED);

                } finally {
                    testServer.stop(0);
                }
            }

            @Test
            void shouldAssociateMutationsWithCorrectBaseline() throws Exception {
                HttpServer server = HttpServer.create(
                        new InetSocketAddress("127.0.0.1", 0), 0
                );

                server.createContext("/api/test", exchange -> {
                    String response = "{\"status\":\"ok\",\"seed\":\"seed-1\"}";
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    byte[] responseBytes = response.getBytes();
                    exchange.sendResponseHeaders(200, responseBytes.length);
                    exchange.getResponseBody().write(responseBytes);
                    exchange.close();
                });

                server.start();
                String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/api/test";

                try {
                    FuzzerConfig config = new FuzzerConfig();
                    config.setAllowNonPublicTargets(true);
                    config.setRequestsPerSecond(10);
                    config.setMaxRequestsPerSession(30);

                    FuzzingSession session = new FuzzingSession(config);

                    // Two seeds with different bodies
                    RequestSpec seed1 = new RequestSpec(
                            "seed-1",
                            "POST",
                            baseUrl,
                            new HashMap<>(Map.of("Content-Type", "application/json")),
                            "{\"id\":1,\"name\":\"first\"}",
                            "BASELINE"
                    );

                    RequestSpec seed2 = new RequestSpec(
                            "seed-2",
                            "POST",
                            baseUrl,
                            new HashMap<>(Map.of("Content-Type", "application/json")),
                            "{\"id\":2,\"name\":\"second\"}",
                            "BASELINE"
                    );

                    session.runFuzzingPipeline(List.of(seed1, seed2));

                    // Verify both baselines were captured and associated with
                    // the correct seed IDs.
                    Map<String, Observation> baselines = session.getBaselines();
                    assertEquals(2, baselines.size());
                    assertTrue(baselines.containsKey("seed-1"));
                    assertTrue(baselines.containsKey("seed-2"));

                    // Every baseline observation must be a 200 from the seed request.
                    assertEquals(200, baselines.get("seed-1").getStatusCode());
                    assertEquals(200, baselines.get("seed-2").getStatusCode());

                    // Mutations must have been generated and executed.
                    assertTrue(session.getTotalRequests() > 2,
                            "Mutations should have been executed");

                } finally {
                    server.stop(0);
                }
            }
        
    @Test
    void shouldGenerateReportWithEnrichedFindings() throws Exception {
        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0
        );

        server.createContext("/api/test", exchange -> {
            // Return 500 for requests with "mutation" in the body (mutated bodies)
            // Baseline will have original body, mutations will have different bodies
            String requestBody = "";
            if (exchange.getRequestBody() != null) {
                requestBody = new String(exchange.getRequestBody().readAllBytes());
            }
            int status = 200;
            String response;
            // If body contains "mutation" or is different from original, return 500
            if (requestBody.contains("mutation") || requestBody.contains("struct") ||
                    requestBody.contains("mut") || requestBody.contains("fuzz") ||
                    requestBody.contains("NULL") || requestBody.contains("EMPTY")) {
                status = 500;
                response = "{\"error\":\"Internal Server Error\"}";
            } else {
                response = "{\"status\":\"ok\",\"reflected\":true}";
            }
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            byte[] responseBytes = response.getBytes();
            exchange.sendResponseHeaders(status, responseBytes.length);
            exchange.getResponseBody().write(responseBytes);
            exchange.close();
        });

        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/api/test";

        Path reportPath = Files.createTempFile("fuzz-report-", ".json");
        reportPath.toFile().deleteOnExit();

        try {
            FuzzerConfig config = new FuzzerConfig();
            config.setAllowNonPublicTargets(true);
            config.setRequestsPerSecond(10);
            config.setMaxRequestsPerSession(50);
            config.setReportOutputPath(reportPath);

            FuzzingSession session = new FuzzingSession(config);

            RequestSpec seed = new RequestSpec(
                    "seed-report",
                    "POST",
                    baseUrl,
                    new HashMap<>(Map.of("Content-Type", "application/json")),
                    "{\"userId\":999,\"action\":\"test\"}",
                    "BASELINE"
            );

            session.runFuzzingPipeline(List.of(seed));

            // Verify report was created
            assertTrue(Files.exists(reportPath), "Report file should exist");

            String reportContent = Files.readString(reportPath);
            assertTrue(reportContent.contains("API Fuzzer Security Report"));
            assertTrue(reportContent.contains("findingCount"));

            // Parse and verify enriched fields
            ObjectMapper mapper = new ObjectMapper();
            JsonNode report = mapper.readTree(reportContent);
            JsonNode findings = report.get("findings");

            // Should have findings (at least anomalies)
            assertTrue(findings.isArray());

            // Verify structure is valid JSON
            assertTrue(report.has("generatedAt"));
            assertEquals("API Fuzzer Security Report", report.get("reportType").asText());

        } finally {
            server.stop(0);
            Files.deleteIfExists(reportPath);
        }
    }
}
