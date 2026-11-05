package com.apifuzzer;

import com.apifuzzer.config.CollegePortalConfig;
import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.engine.FuzzingSession;
import com.apifuzzer.model.Finding;
import com.apifuzzer.model.Observation;
import com.apifuzzer.auth.AuthProfileManager;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class FuzzerRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzerRunner <config.json> <report.json>");
            System.exit(1);
        }

        String configPath = args[0];
        String reportPath = args[1];

        System.out.println("[INFO] Loading config from: " + configPath);
        
        ObjectMapper mapper = new ObjectMapper();
        CollegePortalConfig config = mapper.readValue(new File(configPath), CollegePortalConfig.class);
        
        // Override for local testing
        FuzzerConfig fuzzerConfig = config.toFuzzerConfig(Path.of(reportPath), new AuthProfileManager());
        fuzzerConfig.setAllowNonPublicTargets(true); // Allow localhost
        fuzzerConfig.setRequestsPerSecond(10);
        fuzzerConfig.setMaxRequestsPerSession(300);

        List<com.apifuzzer.model.RequestSpec> seeds = config.buildSeedRequests();
        
        System.out.println("[INFO] Loaded " + seeds.size() + " seed requests");
        System.out.println("[INFO] Starting fuzzing session...");
        System.out.println("[INFO] Report will be written to: " + reportPath);

        FuzzingSession session = new FuzzingSession(fuzzerConfig);
        List<Observation> results = session.runFuzzingPipeline(seeds);

        System.out.println("\n=== SESSION COMPLETE ===");
        System.out.println("State: " + session.getState());
        System.out.println("Total requests: " + session.getTotalRequests());
        System.out.println("Observations: " + results.size());
        System.out.println("Findings: " + session.getFindings().size());
        System.out.println("Strategy scores: " + session.getStrategyScores());

        List<Finding> findings = session.getFindings();
        if (!findings.isEmpty()) {
            System.out.println("\n=== FINDINGS ===");
            for (Finding f : findings) {
                System.out.printf("  [%s] %s (severity=%s, confidence=%s)%n",
                    f.getOracleType(), f.getTitle(), f.getSeverity(), f.getConfidence());
                System.out.printf("    Request: %s | Strategy: %s%n",
                    f.getRequestId(), f.getOracleType());
                System.out.printf("    Evidence: %s%n", f.getEvidence().substring(0, Math.min(120, f.getEvidence().length())) + "...");
            }
        } else {
            System.out.println("\nNo findings detected.");
        }

        // Verify report file
        if (Files.exists(Path.of(reportPath))) {
            String reportContent = Files.readString(Path.of(reportPath));
            System.out.println("\n[INFO] Report written to: " + reportPath);
            System.out.println("[INFO] Report size: " + reportContent.length() + " bytes");
            
            // Pretty print first finding
            com.fasterxml.jackson.databind.JsonNode report = new ObjectMapper().readTree(reportContent);
            if (report.has("findings") && report.get("findings").isArray() && report.get("findings").size() > 0) {
                System.out.println("\n=== SAMPLE REPORT ENTRY ===");
                System.out.println(report.get("findings").get(0).toPrettyString());
            }
        } else {
            System.out.println("\n[WARN] Report file not created (no findings or path issue)");
        }
    }
}