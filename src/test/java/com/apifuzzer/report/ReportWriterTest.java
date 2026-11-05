package com.apifuzzer.report;

import com.apifuzzer.model.Finding;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportWriterTest {

    @TempDir
    Path tempDir;

    private final ReportWriter reportWriter = new ReportWriter();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldWriteFindingsToJson() throws Exception {

        Finding finding = new Finding(
                "request-1",
                "SENSITIVE_DATA",
                "Sensitive information exposed",
                "MEDIUM",
                "LOW",
                "{\"access_token\":\"secret-value\",\"username\":\"alice\"}",
                "Review the API response"
        );

        Path output = tempDir.resolve("report.json");

        reportWriter.writeFindings(List.of(finding), output);

        assertTrue(Files.exists(output));

        JsonNode report = objectMapper.readTree(output.toFile());

        assertEquals(1, report.get("findingCount").asInt());
        assertEquals(
                "API Fuzzer Security Report",
                report.get("reportType").asText()
        );

        assertEquals(
                "Sensitive information exposed",
                report.get("findings").get(0).get("title").asText()
        );
    }

    @Test
    void shouldRedactSecretsFromReport() throws Exception {

        Finding finding = new Finding(
                "request-2",
                "SENSITIVE_DATA",
                "Token exposed",
                "HIGH",
                "MEDIUM",
                "{\"access_token\":\"super-secret-token\"}",
                "Rotate the exposed token"
        );

        Path output = tempDir.resolve("secure/report.json");

        reportWriter.writeFindings(List.of(finding), output);

        String reportContent = Files.readString(output);

        assertFalse(reportContent.contains("super-secret-token"));
        assertTrue(reportContent.contains("[REDACTED]"));
    }

    @Test
    void shouldGenerateReportWithNoFindings() throws Exception {

        Path output = tempDir.resolve("empty-report.json");

        reportWriter.writeFindings(List.of(), output);

        JsonNode report = objectMapper.readTree(output.toFile());

        assertEquals(0, report.get("findingCount").asInt());
        assertTrue(report.get("findings").isArray());
        assertEquals(0, report.get("findings").size());
    }

    @Test
    void shouldRejectNullFindings() {

        Path output = tempDir.resolve("report.json");

        assertThrows(
                IllegalArgumentException.class,
                () -> reportWriter.writeFindings(null, output)
        );
    }
}
