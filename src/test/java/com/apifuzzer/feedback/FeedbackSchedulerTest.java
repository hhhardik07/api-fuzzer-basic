
package com.apifuzzer.feedback;

import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FeedbackSchedulerTest {

    private RequestSpec request(String id, String strategy) {
        RequestSpec request = new RequestSpec();
        request.setId(id);
        request.setMethod("POST");
        request.setUrl("http://localhost:8080/api/test");
        request.setTestStrategy(strategy);
        return request;
    }

 private Observation observation(String id, int status, String body) {
    return new Observation(
            id,
            status,
            body,
            java.util.Map.of(
                    "Content-Type",
                    List.of("application/json")
            ),
            100L
    );
}

    @Test
    void shouldReturnNullWhenQueueIsEmpty() {
        FeedbackScheduler scheduler = new FeedbackScheduler();

        assertNull(scheduler.pollNext());
        assertFalse(scheduler.hasPendingRequests());
    }

    @Test
    void shouldPrioritizeHigherScoredStrategy() {
        FeedbackScheduler scheduler = new FeedbackScheduler();

        RequestSpec first = request("r1", "MUTATION:NULL_username");
        RequestSpec second = request("r2", "MUTATION:EMPTY_email");

        Observation baseline = observation("baseline", 200, "{\"ok\":true}");
        Observation novel = observation("r1", 500, "{\"error\":\"new response\"}");

        scheduler.recordOutcome(
                first,
                baseline,
                novel,
                List.of()
        );

        scheduler.submit(first);
        scheduler.submit(second);

        assertEquals("r1", scheduler.pollNext().getId());
    }

    @Test
    void shouldRewardFindings() {
        FeedbackScheduler scheduler = new FeedbackScheduler();

        RequestSpec request = request("r1", "MUTATION:NULL_username");

        Observation baseline = observation("baseline", 200, "{\"ok\":true}");
        Observation actual = observation("r1", 200, "{\"ok\":true}");

        Finding finding = new Finding(
                "r1",
                "ORACLE_TEST",
                "Test finding",
                "LOW",
                "HIGH",
                "Test evidence",
                "Test recommendation"
        );

        scheduler.recordOutcome(
                request,
                baseline,
                actual,
                List.of(finding)
        );

        assertTrue(scheduler.getStrategyScore("NULL") > 0);
    }

    @Test
    void shouldPenalizeDuplicateResponses() {
        FeedbackScheduler scheduler = new FeedbackScheduler();

        RequestSpec request = request("r1", "MUTATION:NULL_username");

        Observation baseline = observation("baseline", 200, "{\"ok\":true}");
        Observation actual = observation("r1", 200, "{\"ok\":true}");

        scheduler.recordOutcome(request, baseline, actual, List.of());
        double firstScore = scheduler.getStrategyScore("NULL");

        scheduler.recordOutcome(request, baseline, actual, List.of());
        double secondScore = scheduler.getStrategyScore("NULL");

        assertTrue(secondScore < firstScore);
    }

    @Test
    void shouldNotRewardFailedRequests() {
        FeedbackScheduler scheduler = new FeedbackScheduler();

        RequestSpec request = request("r1", "MUTATION:NULL_username");

        Observation failed = observation("r1", 0, "");
        failed.setErrorMessage("Connection failed");

        scheduler.recordOutcome(
                request,
                null,
                failed,
                List.of()
        );

        assertEquals(-0.5, scheduler.getStrategyScore("NULL"), 0.0001);
    }
}

