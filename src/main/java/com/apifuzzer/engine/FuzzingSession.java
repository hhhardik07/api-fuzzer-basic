package com.apifuzzer.engine;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.execution.HttpExecutor;
import com.apifuzzer.execution.RequestLimiter;
import com.apifuzzer.generation.MutationEngine;
import com.apifuzzer.generation.MutationStrategy;
import com.apifuzzer.generation.PayloadMutator;
import com.apifuzzer.generation.StructuralMutator;
import com.apifuzzer.feedback.FeedbackScheduler;
import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.oracle.OracleEngine;
import com.apifuzzer.report.ReportWriter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class FuzzingSession {

    public enum State {
        IDLE,
        RUNNING,
        COMPLETED,
        CANCELLED,
        LIMIT_REACHED,
        FAILED
    }

    private final RequestLimiter limiter;
    private final HttpExecutor executor;
    private final MutationEngine mutationEngine;
    private final StructuralMutator structuralMutator;
    private final PayloadMutator payloadMutator;
    private final FeedbackScheduler feedbackScheduler;
    private final OracleEngine oracleEngine;
    private final ReportWriter reportWriter;

    private final List<Observation> observations =
            Collections.synchronizedList(new ArrayList<>());
    private final List<Finding> findings =
            Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Observation> baselines =
            Collections.synchronizedMap(new HashMap<>());

    // Track all requests (baselines + mutations) by ID for report enrichment
    private final Map<String, RequestSpec> requestMetadata =
            Collections.synchronizedMap(new HashMap<>());

    private final AtomicBoolean cancellationRequested =
            new AtomicBoolean(false);

    private volatile State state = State.IDLE;

    private final FuzzerConfig config;

    public FuzzingSession(FuzzerConfig config) {

        if (config == null) {
            throw new IllegalArgumentException(
                    "FuzzerConfig cannot be null"
            );
        }

        this.config = config;

        this.limiter = new RequestLimiter(config);
        this.executor = new HttpExecutor(config, limiter);
        this.mutationEngine = new MutationEngine();
        this.structuralMutator = new StructuralMutator();
        this.payloadMutator = new PayloadMutator();
        this.feedbackScheduler = new FeedbackScheduler();
        this.oracleEngine = new OracleEngine();
        this.reportWriter = new ReportWriter();
    }

    public List<Observation> run(List<RequestSpec> requests) {

        if (requests == null) {
            throw new IllegalArgumentException(
                    "Request list cannot be null"
            );
        }

        if (state != State.IDLE) {
            throw new IllegalStateException(
                    "A session can only be executed once"
            );
        }

        state = State.RUNNING;

        try {
            for (RequestSpec request : requests) {

                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }

                if (limiter.getRemainingRequests() <= 0) {
                    state = State.LIMIT_REACHED;
                    break;
                }

                Observation observation = executor.execute(
                        request,
                        cancellationRequested
                );

                observations.add(observation);

                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }

                if (observation.getErrorMessage() != null
                        && observation.getErrorMessage().contains(
                                "session limit reached")) {
                    state = State.LIMIT_REACHED;
                    break;
                }
            }

            if (state == State.RUNNING) {
                state = cancellationRequested.get()
                        ? State.CANCELLED
                        : State.COMPLETED;
            }

        } catch (RuntimeException e) {
            state = cancellationRequested.get()
                    ? State.CANCELLED
                    : State.FAILED;

            if (!cancellationRequested.get()) {
                throw e;
            }
        }

        return getObservations();
    }

    /**
     * Runs the complete fuzzing pipeline: baseline execution, mutation generation,
     * scheduled execution, oracle evaluation, and feedback-driven prioritization.
     *
     * @param seeds the seed requests to fuzz
     * @return all observations collected during the session
     */
    public List<Observation> runFuzzingPipeline(List<RequestSpec> seeds) {

        if (seeds == null) {
            throw new IllegalArgumentException(
                    "Seed request list cannot be null"
            );
        }

        if (state != State.IDLE) {
            throw new IllegalStateException(
                    "A session can only be executed once"
            );
        }

        state = State.RUNNING;

        try {
            // Phase 1: Execute baselines for all seeds
            for (RequestSpec seed : seeds) {
                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }

                if (limiter.getRemainingRequests() <= 0) {
                    state = State.LIMIT_REACHED;
                    break;
                }

                // Ensure seed has an ID for tracking
                if (seed.getId() == null || seed.getId().isBlank()) {
                    throw new IllegalArgumentException(
                            "Every seed request must have an ID"
                    );
                }

                // Mark seed as its own seed for tracking
                seed.setSeedId(seed.getId());

                Observation baseline = executor.execute(seed, cancellationRequested);
                observations.add(baseline);
                baselines.put(seed.getId(), baseline);

                // Track request metadata for report enrichment
                requestMetadata.put(seed.getId(), seed);

                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }
            }

            // Phase 2: Generate mutations for all seeds
            List<RequestSpec> allMutations = new ArrayList<>();
            for (RequestSpec seed : seeds) {
                if (cancellationRequested.get()) {
                    break;
                }

                // Generate mutations from JSON body mutator
                List<RequestSpec> bodyMutations = mutationEngine.generateMutations(seed);
                for (RequestSpec m : bodyMutations) {
                    m.setSeedId(seed.getId());
                }
                allMutations.addAll(bodyMutations);

                // Generate structural mutations
                List<RequestSpec> structMutations = structuralMutator.mutate(seed, 20);
                for (RequestSpec m : structMutations) {
                    m.setSeedId(seed.getId());
                }
                allMutations.addAll(structMutations);

                // Generate payload mutations
                List<RequestSpec> payloadMutations = payloadMutator.mutate(seed, 20);
                for (RequestSpec m : payloadMutations) {
                    m.setSeedId(seed.getId());
                }
                allMutations.addAll(payloadMutations);
            }

            // Phase 3: Submit all mutations to feedback scheduler
            feedbackScheduler.submitAll(allMutations);

            // Phase 4: Execute mutations in priority order
            while (feedbackScheduler.hasPendingRequests()
                    && !cancellationRequested.get()
                    && limiter.getRemainingRequests() > 0) {

                RequestSpec mutation = feedbackScheduler.pollNext();
                if (mutation == null) {
                    break;
                }

                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }

                if (limiter.getRemainingRequests() <= 0) {
                    state = State.LIMIT_REACHED;
                    break;
                }

                // Track mutation metadata for report enrichment
                requestMetadata.put(mutation.getId(), mutation);

                String seedId = mutation.getSeedId();
                Observation baseline = baselines.get(seedId);

                Observation actual = executor.execute(mutation, cancellationRequested);
                observations.add(actual);

                // Evaluate with oracle
                List<Finding> mutationFindings = oracleEngine.evaluate(
                        mutation, baseline, actual
                );

                if (!mutationFindings.isEmpty()) {
                    findings.addAll(mutationFindings);
                }

                // Record outcome for feedback scheduling
                feedbackScheduler.recordOutcome(
                        mutation, baseline, actual, mutationFindings
                );

                if (cancellationRequested.get()) {
                    state = State.CANCELLED;
                    break;
                }

                if (actual.getErrorMessage() != null
                        && actual.getErrorMessage().contains(
                                "session limit reached")) {
                    state = State.LIMIT_REACHED;
                    break;
                }
            }

            if (state == State.RUNNING) {
                if (limiter.getRemainingRequests() <= 0) {
                    state = State.LIMIT_REACHED;
                } else {
                    state = cancellationRequested.get()
                            ? State.CANCELLED
                            : State.COMPLETED;
                }
            }

            // Generate report if output path is configured
            generateReport();

        } catch (RuntimeException e) {
            state = cancellationRequested.get()
                    ? State.CANCELLED
                    : State.FAILED;

            if (!cancellationRequested.get()) {
                throw e;
            }
        }

        return getObservations();
    }

    private void generateReport() {
        Path reportPath = config.getReportOutputPath();
        if (reportPath != null) {  // Always generate report, even with 0 findings
            try {
                // Build observations map for enrichment
                Map<String, Observation> observationsById = new HashMap<>();
                for (Observation obs : observations) {
                    if (obs.getRequestId() != null) {
                        observationsById.put(obs.getRequestId(), obs);
                    }
                }
                reportWriter.writeFindings(
                        findings,
                        requestMetadata,
                        observationsById,
                        baselines,
                        reportPath
                );
            } catch (IOException e) {
                // Log but don't fail the session
                System.err.println("Failed to write report: " + e.getMessage());
            }
        }
    }

    public void cancel() {
        cancellationRequested.set(true);
        executor.cancelActiveRequest();
    }

    public State getState() {
        return state;
    }

    public List<Observation> getObservations() {
        synchronized (observations) {
            return List.copyOf(observations);
        }
    }

    public List<Finding> getFindings() {
        synchronized (findings) {
            return List.copyOf(findings);
        }
    }

    public Map<String, Observation> getBaselines() {
        synchronized (baselines) {
            return Map.copyOf(baselines);
        }
    }

    public int getTotalRequests() {
        return limiter.getTotalRequests();
    }

    public int getRemainingRequests() {
        return limiter.getRemainingRequests();
    }

    public int getPendingMutationCount() {
        return feedbackScheduler.getPendingCount();
    }

    public Map<String, Double> getStrategyScores() {
        return feedbackScheduler.getStrategyScores();
    }
}