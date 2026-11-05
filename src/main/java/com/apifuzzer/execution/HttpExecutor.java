
package com.apifuzzer.execution;

import com.apifuzzer.auth.AuthProfileResolver;
import com.apifuzzer.config.FuzzerConfig;
import com.apifuzzer.model.Observation;
import com.apifuzzer.model.RequestSpec;
import com.apifuzzer.security.TargetAddressValidator;
import com.apifuzzer.security.TargetScope;

import okhttp3.Call;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class HttpExecutor {

    private final FuzzerConfig config;
    private final RequestLimiter limiter;
    private final AuthProfileResolver authResolver;
    private final TargetScope targetScope;
    private final OkHttpClient baseClient;
    private final TargetAddressValidator addressValidator;

    private final SSLSocketFactory testSslSocketFactory;
    private final X509TrustManager testTrustManager;

    private final AtomicReference<Call> activeCall =
            new AtomicReference<>();

    public HttpExecutor() {
        this(new FuzzerConfig(), null, null, null);
    }

    public HttpExecutor(FuzzerConfig config) {
        this(config, null, null, null);
    }

    public HttpExecutor(FuzzerConfig config, RequestLimiter limiter) {
        this(config, limiter, null, null);
    }

    public HttpExecutor(
            FuzzerConfig config,
            RequestLimiter limiter,
            AuthProfileResolver authProfileResolver
    ) {
        this(config, limiter, authProfileResolver, null);
    }

    public HttpExecutor(
            FuzzerConfig config,
            RequestLimiter limiter,
            AuthProfileResolver authProfileResolver,
            TargetScope targetScope
    ) {
        this(
                config,
                limiter,
                authProfileResolver,
                targetScope,
                null,
                null
        );
    }

    HttpExecutor(
            FuzzerConfig config,
            RequestLimiter limiter,
            AuthProfileResolver authProfileResolver,
            TargetScope targetScope,
            SSLSocketFactory testSslSocketFactory,
            X509TrustManager testTrustManager
    ) {
        this(
                config,
                limiter,
                authProfileResolver,
                targetScope,
                testSslSocketFactory,
                testTrustManager,
                null
        );
    }

    HttpExecutor(
            FuzzerConfig config,
            RequestLimiter limiter,
            AuthProfileResolver authProfileResolver,
            TargetScope targetScope,
            SSLSocketFactory testSslSocketFactory,
            X509TrustManager testTrustManager,
            TargetAddressValidator addressValidator
    ) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "FuzzerConfig cannot be null"
            );
        }

        if ((testSslSocketFactory == null)
                != (testTrustManager == null)) {
            throw new IllegalArgumentException(
                    "Both TLS test components must be supplied together"
            );
        }

        this.config = config;
        this.limiter = limiter != null
                ? limiter
                : new RequestLimiter(config);

        this.authResolver = authProfileResolver;
        this.targetScope = targetScope;

        this.addressValidator = addressValidator != null
                ? addressValidator
                : new TargetAddressValidator();

        this.testSslSocketFactory = testSslSocketFactory;
        this.testTrustManager = testTrustManager;

        OkHttpClient.Builder baseBuilder =
                new OkHttpClient.Builder()
                        .proxy(Proxy.NO_PROXY)
                        .connectionPool(
                                new ConnectionPool(
                                        5,
                                        5,
                                        TimeUnit.SECONDS
                                )
                        )
                        .connectTimeout(Duration.ofSeconds(
                                config.getRequestTimeoutSeconds()
                        ))
                        .readTimeout(Duration.ofSeconds(
                                config.getRequestTimeoutSeconds()
                        ))
                        .writeTimeout(Duration.ofSeconds(
                                config.getRequestTimeoutSeconds()
                        ))
                        .callTimeout(Duration.ofSeconds(
                                config.getRequestTimeoutSeconds()
                        ))
                        .followRedirects(false)
                        .followSslRedirects(false)
                        .retryOnConnectionFailure(false);

        if (testSslSocketFactory != null) {
            baseBuilder.sslSocketFactory(
                    testSslSocketFactory,
                    testTrustManager
            );
        }

        this.baseClient = baseBuilder.build();
    }

    /**
     * Executes a request without an external cancellation token.
     */
    public Observation execute(RequestSpec originalSpec) {
        return execute(originalSpec, new AtomicBoolean(false));
    }

    /**
     * Executes a request while observing a session cancellation token.
     */
    public Observation execute(
            RequestSpec originalSpec,
            AtomicBoolean cancellationToken
    ) {
        long startTime = System.nanoTime();

        if (cancellationToken == null) {
            throw new IllegalArgumentException(
                    "Cancellation token cannot be null"
            );
        }

        try {
            if (originalSpec == null) {
                throw new IllegalArgumentException(
                        "RequestSpec cannot be null"
                );
            }

            if (cancellationToken.get()) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        "Request cancelled"
                );
            }

            if (originalSpec.getUrl() == null
                    || originalSpec.getUrl().isBlank()) {
                throw new IllegalArgumentException(
                        "Request URL is missing"
                );
            }

            RequestSpec spec = originalSpec;

            if (authResolver != null) {
                spec = authResolver.resolveRequest(originalSpec);
            }

            URI uri = URI.create(spec.getUrl());

            String method = spec.getMethod() == null
                    ? ""
                    : spec.getMethod().toUpperCase(Locale.ROOT);

            validateTarget(uri);

            if (!config.getAllowedMethods().contains(method)) {
                throw new IllegalArgumentException(
                        "HTTP method is not allowed"
                );
            }

            if (targetScope != null) {
                targetScope.validate(uri, method);
            }

            if (cancellationToken.get()) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        "Request cancelled"
                );
            }

            // Resolve and validate DNS exactly once.
            List<InetAddress> pinnedAddresses =
                    addressValidator.resolveAndValidate(
                            uri,
                            config.isAllowNonPublicTargets()
                    );

            if (cancellationToken.get()) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        "Request cancelled"
                );
            }

            OkHttpClient client = createPinnedClient(
                    uri,
                    pinnedAddresses
            );

            Request.Builder requestBuilder =
                    new Request.Builder()
                            .url(spec.getUrl());

            if (spec.getHeaders() != null) {
                for (Map.Entry<String, String> header :
                        spec.getHeaders().entrySet()) {

                    if (header.getKey() == null
                            || header.getValue() == null) {
                        throw new IllegalArgumentException(
                                "Header names and values cannot be null"
                        );
                    }

                    requestBuilder.addHeader(
                            header.getKey(),
                            header.getValue()
                    );
                }
            }

            String body = spec.getBody();
            RequestBody requestBody = null;

            if (body != null && !body.isEmpty()) {
                requestBody = RequestBody.create(
                        body.getBytes(StandardCharsets.UTF_8),
                        null
                );
            } else if (method.equals("POST")
                    || method.equals("PUT")
                    || method.equals("PATCH")) {
                requestBody = RequestBody.create(
                        new byte[0],
                        null
                );
            }

            requestBuilder.method(method, requestBody);

            if (cancellationToken.get()) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        "Request cancelled"
                );
            }

       if (!limiter.acquire(cancellationToken)) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        cancellationToken.get()
                                ? "Request cancelled"
                                : "Request rejected: session limit reached "
                                + "or limiter interrupted"
                );
            }

            if (cancellationToken.get()) {
                return createErrorObservation(
                        originalSpec,
                        startTime,
                        "Request cancelled"
                );
            }

            Call call = client.newCall(requestBuilder.build());

            // Register before executing so cancellation can reach this call.
            activeCall.set(call);

            // Handles cancellation that happened immediately before
            // the active call was registered.
            if (cancellationToken.get()
                    || Thread.currentThread().isInterrupted()) {
                call.cancel();
            }

            try (Response response = call.execute()) {

                String responseText = "";
                ResponseBody responseBody = response.body();

                if (responseBody != null) {
                    try (InputStream stream =
                                 responseBody.byteStream()) {
                        responseText = readLimited(stream);
                    }
                }

                return new Observation(
                        originalSpec.getId(),
                        response.code(),
                        responseText,
                        response.headers().toMultimap(),
                        elapsedMillis(startTime)
                );

            } finally {
                activeCall.compareAndSet(call, null);
            }

        } catch (IOException e) {

            return createErrorObservation(
                    originalSpec,
                    startTime,
                    cancellationToken.get()
                            ? "Request cancelled"
                            : "HTTP execution failed: "
                            + e.getClass().getSimpleName()
            );

        } catch (IllegalArgumentException e) {

            String message = e.getMessage();
            String safeMessage;

            if (message != null && message.contains("allowlist")) {
                safeMessage =
                        "Request rejected: target host is not in the configured allowlist";

            } else if (message != null
                    && (message.contains("scope")
                    || message.contains("outside approved"))) {
                safeMessage =
                        "Request rejected: target is outside configured scope";

            } else if (message != null
                    && message.contains("Only HTTP and HTTPS")) {
                safeMessage =
                        "Request rejected: unsupported URL scheme";

            } else if (message != null
                    && message.contains("Embedded URL credentials")) {
                safeMessage =
                        "Request rejected: embedded URL credentials are not allowed";

            } else if (message != null
                    && message.contains("HTTP method is not allowed")) {
                safeMessage =
                        "Request rejected: HTTP method is not allowed";

            } else if (message != null
                    && message.contains("Header names and values")) {
                safeMessage =
                        "Request rejected: invalid HTTP headers";

            } else if (message != null
                    && message.contains("Ambiguous path encoding")) {
                safeMessage =
                        "Request rejected: ambiguous path encoding";

            } else if (message != null
                    && message.contains("Dot segments")) {
                safeMessage =
                        "Request rejected: path traversal segments are not allowed";

            } else if (message != null
                    && message.contains("non-public")) {
                safeMessage =
                        "Request rejected: target resolves to a non-public address";

            } else if (message != null
                    && message.contains("could not be resolved")) {
                safeMessage =
                        "Request rejected: target hostname could not be resolved";

            } else {
                safeMessage =
                        "Request rejected: invalid request configuration";
            }

            return createErrorObservation(
                    originalSpec,
                    startTime,
                    safeMessage
            );

        } catch (RuntimeException e) {

            return createErrorObservation(
                    originalSpec,
                    startTime,
                    "Request execution failed: "
                            + e.getClass().getSimpleName()
            );
        }
    }

    /**
     * Cancels the currently executing HTTP request, if one exists.
     */
    public void cancelActiveRequest() {
        Call call = activeCall.get();

        if (call != null) {
            call.cancel();
        }
    }

    private OkHttpClient createPinnedClient(
            URI uri,
            List<InetAddress> pinnedAddresses
    ) {
        String expectedHost = normalizeHost(uri.getHost());

        return baseClient.newBuilder()
                .dns(hostname -> {
                    if (!normalizeHost(hostname).equals(expectedHost)) {
                        throw new UnknownHostException(
                                "Unexpected hostname requested"
                        );
                    }

                    return pinnedAddresses;
                })
                .build();
    }

    private void validateTarget(URI uri) {

        if (uri == null) {
            throw new IllegalArgumentException(
                    "Target URI is missing"
            );
        }

        String scheme = uri.getScheme();

        if (scheme == null
                || (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException(
                    "Only HTTP and HTTPS URLs are supported"
            );
        }

        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException(
                    "Target host is missing"
            );
        }

        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException(
                    "Embedded URL credentials are not allowed"
            );
        }

        String normalizedHost = normalizeHost(host);

        Set<String> allowedHosts = config.getAllowedHosts();

        boolean hostAllowed = allowedHosts.stream()
                .map(this::normalizeHost)
                .anyMatch(normalizedHost::equals);

        if (!hostAllowed) {
            throw new IllegalArgumentException(
                    "Target host is not in the configured allowlist"
            );
        }
    }

    private String normalizeHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);

        if (normalized.endsWith(".")) {
            normalized = normalized.substring(
                    0,
                    normalized.length() - 1
            );
        }

        return normalized;
    }

    private String readLimited(InputStream inputStream)
            throws IOException {

        int maximumBytes = config.getMaxResponseSizeBytes();

        try (ByteArrayOutputStream output =
                     new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int totalBytes = 0;
            int bytesRead;

            while (totalBytes < maximumBytes
                    && (bytesRead = inputStream.read(
                            buffer,
                            0,
                            Math.min(
                                    buffer.length,
                                    maximumBytes - totalBytes
                            )
                    )) != -1) {

                output.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }

            return output.toString(StandardCharsets.UTF_8);
        }
    }

    private long elapsedMillis(long startTime) {
        return Duration.ofNanos(
                System.nanoTime() - startTime
        ).toMillis();
    }

    private Observation createErrorObservation(
            RequestSpec spec,
            long startTime,
            String errorMessage
    ) {
        String requestId = spec == null
                ? "unknown"
                : spec.getId();

        Observation observation = new Observation(
                requestId,
                0,
                "",
                Map.of(),
                elapsedMillis(startTime)
        );

        observation.setErrorMessage(errorMessage);

        return observation;
    }
}

