
package com.apifuzzer.execution;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

class HttpExecutorHttpsTest {

    private static class HttpsFixture implements AutoCloseable {

        final MockWebServer server;
        final HeldCertificate serverCertificate;

        HttpsFixture() throws Exception {
            serverCertificate = new HeldCertificate.Builder()
                    .commonName("localhost")
                    .addSubjectAlternativeName("localhost")
                    .build();

            HandshakeCertificates serverCertificates =
                    new HandshakeCertificates.Builder()
                            .heldCertificate(serverCertificate)
                            .build();

            server = new MockWebServer();
            server.useHttps(
                    serverCertificates.sslSocketFactory(),
                    false
            );
            server.start();
        }

        String url() {
            return server.url("/api/test").toString();
        }

        @Override
        public void close() throws Exception {
            server.shutdown();
        }
    }

    @Test
    void shouldExecuteRequestWithTrustedHttpsCertificate()
            throws Exception {

        try (HttpsFixture fixture = new HttpsFixture()) {

            fixture.server.enqueue(
                    new MockResponse()
                            .setResponseCode(200)
                            .setBody("secure response")
            );

            HandshakeCertificates clientCertificates =
                    new HandshakeCertificates.Builder()
                            .addTrustedCertificate(
                                    fixture.serverCertificate.certificate()
                            )
                            .build();

            FuzzerConfig config = new FuzzerConfig();
            config.setAllowNonPublicTargets(true);

            HttpExecutor executor = new HttpExecutor(
                    config,
                    null,
                    null,
                    null,
                    clientCertificates.sslSocketFactory(),
                    clientCertificates.trustManager()
            );

            RequestSpec request = new RequestSpec(
                    "https-trusted",
                    "GET",
                    fixture.url(),
                    new HashMap<>(),
                    null,
                    "BASELINE"
            );

            Observation observation = executor.execute(request);

            assertEquals(200, observation.getStatusCode());
            assertEquals(
                    "secure response",
                    observation.getResponseBody()
            );
            assertNull(observation.getErrorMessage());
        }
    }

    @Test
    void shouldRejectUntrustedHttpsCertificate()
            throws Exception {

        try (HttpsFixture fixture = new HttpsFixture()) {

            fixture.server.enqueue(
                    new MockResponse()
                            .setResponseCode(200)
                            .setBody("should not be received")
            );

            HeldCertificate unrelatedCertificate =
                    new HeldCertificate.Builder()
                            .commonName("untrusted.localhost")
                            .addSubjectAlternativeName("untrusted.localhost")
                            .build();

            HandshakeCertificates untrustedClientCertificates =
                    new HandshakeCertificates.Builder()
                            .addTrustedCertificate(
                                    unrelatedCertificate.certificate()
                            )
                            .build();

            FuzzerConfig config = new FuzzerConfig();
            config.setAllowNonPublicTargets(true);

            HttpExecutor executor = new HttpExecutor(
                    config,
                    null,
                    null,
                    null,
                    untrustedClientCertificates.sslSocketFactory(),
                    untrustedClientCertificates.trustManager()
            );

            RequestSpec request = new RequestSpec(
                    "https-untrusted",
                    "GET",
                    fixture.url(),
                    new HashMap<>(),
                    null,
                    "BASELINE"
            );

            Observation observation = executor.execute(request);

            assertEquals(0, observation.getStatusCode());
            assertNotNull(observation.getErrorMessage());
            assertTrue(
                    observation.getErrorMessage()
                            .contains("HTTP execution failed")
            );
        }
    }
}

