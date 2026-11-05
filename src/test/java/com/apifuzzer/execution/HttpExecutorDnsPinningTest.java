
package com.apifuzzer.execution;

import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.security.TargetAddressValidator;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import java.net.InetAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HttpExecutorDnsPinningTest {

    @Test
    void shouldConnectUsingOnlyValidatedPinnedAddress()
            throws Exception {

        HeldCertificate serverCertificate =
                new HeldCertificate.Builder()
                        .commonName("pinned.test")
                        .addSubjectAlternativeName("pinned.test")
                        .build();

        HandshakeCertificates serverTls =
                new HandshakeCertificates.Builder()
                        .heldCertificate(serverCertificate)
                        .build();

        HandshakeCertificates clientTls =
                new HandshakeCertificates.Builder()
                        .addTrustedCertificate(
                                serverCertificate.certificate()
                        )
                        .build();

        try (MockWebServer server = new MockWebServer()) {

            server.useHttps(
                    serverTls.sslSocketFactory(),
                    false
            );

            server.start();

            server.enqueue(
                    new MockResponse()
                            .setResponseCode(200)
                            .setBody("DNS pinned successfully")
            );

            // This hostname  has no public DNS record. ye intentional thaaa
            String targetUrl = "https://pinned.test:"
                    + server.getPort()
                    + "/api/test";

            InetAddress pinnedAddress = InetAddress.getByAddress(
                    "pinned.test",
                    new byte[]{127, 0, 0, 1}
            );

            AtomicInteger resolutionCount =
                    new AtomicInteger(0);

            TargetAddressValidator testValidator =
                    new TargetAddressValidator() {

                @Override
                public List<InetAddress> resolveAndValidate(
                        URI uri,
                        boolean allowNonPublicAddresses
                ) {
                    resolutionCount.incrementAndGet();

                    assertEquals("pinned.test", uri.getHost());

                    return List.of(pinnedAddress);
                }
            };

            FuzzerConfig config = new FuzzerConfig();
            config.setAllowedHosts(Set.of("pinned.test"));
            config.setAllowNonPublicTargets(true);

            SSLSocketFactory socketFactory =
                    clientTls.sslSocketFactory();

            X509TrustManager trustManager =
                    clientTls.trustManager();

            HttpExecutor executor = new HttpExecutor(
                    config,
                    null,
                    null,
                    null,
                    socketFactory,
                    trustManager,
                    testValidator
            );

            RequestSpec request = new RequestSpec(
                    "dns-pinning-test",
                    "GET",
                    targetUrl,
                    new HashMap<>(),
                    null,
                    "BASELINE"
            );

            Observation observation = executor.execute(request);

            assertEquals(
                    200,
                    observation.getStatusCode(),
                    "Request should reach the server using pinned DNS"
            );

            assertEquals(
                    "DNS pinned successfully",
                    observation.getResponseBody()
            );

            assertNull(observation.getErrorMessage());

            assertEquals(
                    1,
                    resolutionCount.get(),
                    "Address validation should happen exactly once"
            );

            assertEquals(
                    1,
                    server.getRequestCount()
            );
        }
    }
}

