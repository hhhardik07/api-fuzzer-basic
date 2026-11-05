package com.apifuzzer.model;

import java.util.HashMap;
import java.util.Map;

public class RequestSpec {

    private String id;
    private String method;
    private String url;
    private Map<String, String> headers;
    private String body;
    private String testStrategy;
    private String authProfile;
    private String seedId;

    public RequestSpec() {
        this.headers = new HashMap<>();
        this.testStrategy = "BASELINE";
    }

    public String getAuthProfile() {
        return authProfile;
    }

    public void setAuthProfile(String authProfile) {
        this.authProfile = authProfile;
    }

    public String getSeedId() {
        return seedId;
    }

    public void setSeedId(String seedId) {
        this.seedId = seedId;
    }

    public RequestSpec(
            String id,
            String method,
            String url,
            Map<String, String> headers,
            String body,
            String testStrategy
    ) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.headers = headers != null ? headers : new HashMap<>();
        this.body = body;
        this.testStrategy = testStrategy;
    }

    public String getId() {
        return id;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public String getTestStrategy() {
        return testStrategy;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public void setTestStrategy(String testStrategy) {
        this.testStrategy = testStrategy;
    }
}