
package com.apifuzzer.oracle;

import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OracleEngineTest {

    private final OracleEngine engine = new OracleEngine();

    private RequestSpec createRequest() {
        return new RequestSpec(
                "test-001",
                "POST",
                "http://localhost:8765/api/test",
                new HashMap<>(),
                "{}",
                "MUTATION:NULL"
        );
    }

    private Observation createObservation(
            int status,
            String body
    ) {
        return new Observation(
                "test-001",
                status,
                body,
                Map.of("Content-Type", List.of("application/json")),
                100
        );
    }

    @Test
    void shouldDetectUnexpectedServerError() {

        Observation baseline = createObservation(
                200, "{\"message\":\"ok\"}"
        );

        Observation actual = createObservation(
                500, "{\"error\":\"Internal Server Error\"}"
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), baseline, actual
        );

        assertTrue(findings.stream().anyMatch(
                f -> f.getOracleType().equals("STATUS_ORACLE")
        ));
    }

    @Test
    void shouldDetectStackTraceDisclosure() {

        Observation actual = createObservation(
                500,
                "Exception in thread \"main\" java.lang.RuntimeException"
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), null, actual
        );

        assertTrue(findings.stream().anyMatch(
                f -> f.getOracleType().equals(
                        "ERROR_DISCLOSURE_ORACLE")
        ));
    }

    @Test
    void shouldDetectDatabaseError() {

        Observation actual = createObservation(
                500,
                "SQLSTATE[42000]: Syntax error in SQL statement"
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), null, actual
        );

        assertTrue(findings.stream().anyMatch(
                f -> f.getOracleType().equals(
                        "DATABASE_ERROR_ORACLE")
        ));
    }

    @Test
    void shouldDetectSensitiveFields() {

        Observation actual = createObservation(
                200,
                """
                {
                    "username": "test-student",
                    "password_hash": "example-hash",
                    "access_token": "example-token"
                }
                """
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), null, actual
        );

        assertTrue(findings.stream().anyMatch(
                f -> f.getOracleType().equals(
                        "INFORMATION_DISCLOSURE_ORACLE")
        ));
    }

    @Test
    void shouldDetectResponseAnomaly() {

        Observation baseline = createObservation(
                200, "{\"message\":\"ok\"}"
        );

        Observation actual = createObservation(
                403, "{\"error\":\"Forbidden\"}"
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), baseline, actual
        );

        assertTrue(findings.stream().anyMatch(
                f -> f.getOracleType().equals(
                        "RESPONSE_ANOMALY_ORACLE")
        ));
    }

    @Test
    void shouldNotFlagOrdinarySuccessfulResponse() {

        Observation baseline = createObservation(
                200, "{\"message\":\"ok\"}"
        );

        Observation actual = createObservation(
                200, "{\"message\":\"ok\"}"
        );

        List<Finding> findings = engine.evaluate(
                createRequest(), baseline, actual
        );

        assertTrue(findings.isEmpty());
    }
}

