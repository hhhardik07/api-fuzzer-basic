package com.apifuzzer.security;

import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TargetScope {

    private static final Pattern ENCODED_PATH_SEPARATOR_OR_DOT =
            Pattern.compile("%2f|%5c|%2e", Pattern.CASE_INSENSITIVE);

    private final Set<String> allowedHosts;
    private final Set<String> allowedMethods;
    private final Set<String> allowedPathPrefixes;

    public TargetScope(
            Set<String> allowedHosts,
            Set<String> allowedMethods,
            Set<String> allowedPathPrefixes
    ) {
        if (allowedHosts == null || allowedHosts.isEmpty()
                || allowedMethods == null || allowedMethods.isEmpty()
                || allowedPathPrefixes == null || allowedPathPrefixes.isEmpty()) {
            throw new IllegalArgumentException("Scope rules cannot be empty");
        }

        this.allowedHosts = allowedHosts.stream()
                .map(host -> host.toLowerCase(Locale.ROOT))
                .map(host -> host.endsWith(".")
                        ? host.substring(0, host.length() - 1)
                        : host)
                .collect(Collectors.toUnmodifiableSet());

        this.allowedMethods = allowedMethods.stream()
                .map(method -> method.toUpperCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());

        this.allowedPathPrefixes = allowedPathPrefixes.stream()
                .map(TargetScope::normalizePrefix)
                .collect(Collectors.toUnmodifiableSet());
    }

    public void validate(URI uri, String method) {

        if (uri == null || method == null || method.isBlank()) {
            throw new IllegalArgumentException("URI and method are required");
        }

        String scheme = uri.getScheme();

        if (scheme == null
                || !(scheme.equalsIgnoreCase("http")
                || scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Only HTTP and HTTPS are allowed");
        }

        if (uri.getHost() == null || uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("Invalid target URI");
        }

        String host = uri.getHost().toLowerCase(Locale.ROOT);

        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        if (!allowedHosts.contains(host)) {
            throw new IllegalArgumentException("Target host is outside approved scope");
        }

        if (!allowedMethods.contains(method.toUpperCase(Locale.ROOT))) {
            throw new IllegalArgumentException("HTTP method is outside approved scope");
        }

        String rawPath = uri.getRawPath();

final String path =
        (rawPath == null || rawPath.isEmpty()) ? "/" : rawPath;

validatePathSyntax(path);

boolean pathAllowed = allowedPathPrefixes.stream()
        .anyMatch(prefix -> matchesPrefix(path, prefix));

        if (!pathAllowed) {
            throw new IllegalArgumentException("Target path is outside approved scope");
        }
    }

    private static String normalizePrefix(String prefix) {

        if (prefix == null || prefix.isBlank() || !prefix.startsWith("/")) {
            throw new IllegalArgumentException("Path prefixes must start with /");
        }

        validatePathSyntax(prefix);

        if (prefix.length() > 1 && prefix.endsWith("/")) {
            return prefix.substring(0, prefix.length() - 1);
        }

        return prefix;
    }

    private static void validatePathSyntax(String path) {

        if (path.contains("\\")
                || ENCODED_PATH_SEPARATOR_OR_DOT.matcher(path).find()) {
            throw new IllegalArgumentException("Ambiguous path encoding is not allowed");
        }

        for (String segment : path.split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Dot segments are not allowed");
            }
        }
    }

    private static boolean matchesPrefix(String path, String prefix) {

        if (prefix.equals("/")) {
            return true;
        }

        return path.equals(prefix) || path.startsWith(prefix + "/");
    }
}
