
package com.apifuzzer.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FindingTest {

    @Test
    void shouldRedactSensitiveJsonEvidence() {
        Finding finding = new Finding(
                "request-1",
                "SENSITIVE_DATA",
                "Sensitive response detected",
                "MEDIUM",
                "LOW",
                "{\"access_token\":\"secret123\",\"username\":\"student\"}",
                "Review exposed response data"
        );

        assertFalse(finding.getEvidence().contains("secret123"));
        assertTrue(finding.getEvidence().contains("[REDACTED]"));
        assertTrue(finding.getEvidence().contains("student"));
    }

    @Test
    void shouldRedactBearerTokensFromEvidence() {
        Finding finding = new Finding(
                "request-1",
                "AUTH_TEST",
                "Authentication issue",
                "LOW",
                "MEDIUM",
                "Server returned Bearer abc.def.ghi",
                "Review authentication handling"
        );

        assertFalse(finding.getEvidence().contains("abc.def.ghi"));
        assertTrue(
                finding.getEvidence().contains("Bearer [REDACTED]")
        );
    }

    @Test
    void shouldKeepFindingImmutable() {
        Finding finding = new Finding(
                "request-1",
                "TEST",
                "Test finding",
                "LOW",
                "HIGH",
                "Safe evidence",
                "Test recommendation"
        );

        assertEquals("Safe evidence", finding.getEvidence());
        assertNotNull(finding.getId());
        assertNotNull(finding.getTimestamp());
    }
}

