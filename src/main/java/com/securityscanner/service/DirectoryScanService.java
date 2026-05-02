package com.securityscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Service
public class DirectoryScanService {

    private static final int CONNECT_TIMEOUT_MS = 2000;
    private static final int READ_TIMEOUT_MS    = 2000;

    private static final String[] COMMON_PATHS = {
            "/admin",
            "/login",
            "/.env",
            "/backup.zip",
            "/config",
            "/.git",
            "/api",
            "/debug",
            "/test"
    };

    public record DirectoryResult(String path, int statusCode, String label) {
        @Override
        public String toString() {
            return path + " → " + statusCode + " (" + label + ")";
        }
    }

    public List<DirectoryResult> scanDirectories(String domain) {
        log.info("[DirectoryScanService] Starting directory scan for domain: {}", domain);

        long start = System.currentTimeMillis();
        List<DirectoryResult> findings = new CopyOnWriteArrayList<>();

        Arrays.stream(COMMON_PATHS)
                .parallel()
                .forEach(path -> {
                    DirectoryResult result = probeUrl(domain, path);
                    if (result != null) {
                        findings.add(result);
                        log.info("[DirectoryScanService] Found: {}", result);
                    }
                });

        long elapsed = System.currentTimeMillis() - start;
        log.info("[DirectoryScanService] Scan completed in {}ms | domain={} | findings={}",
                elapsed, domain, findings);

        return findings;
    }

    private DirectoryResult probeUrl(String domain, String path) {
        String rawUrl = "https://" + domain + path;

        try {
            HttpURLConnection conn = openConnection(rawUrl);
            int status = conn.getResponseCode();
            conn.disconnect();

            if (isInteresting(status)) {
                return new DirectoryResult(path, status, resolveLabel(status));
            }

        } catch (Exception e) {
            // Retry on HTTP if HTTPS fails
            try {
                HttpURLConnection conn = openConnection("http://" + domain + path);
                int status = conn.getResponseCode();
                conn.disconnect();

                if (isInteresting(status)) {
                    return new DirectoryResult(path, status, resolveLabel(status));
                }

            } catch (Exception ignored) {
                log.debug("[DirectoryScanService] Unreachable: {}{}", domain, path);
            }
        }

        return null;
    }

    private HttpURLConnection openConnection(String rawUrl) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(rawUrl).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setInstanceFollowRedirects(false); // ✅ Capture 302 as-is, not silently follow
        conn.setRequestProperty("User-Agent", "SecurityScanner/1.0");
        return conn;
    }

    private boolean isInteresting(int status) {
        return status == 200 || status == 403 || status == 302 || status == 401;
    }

    private String resolveLabel(int status) {
        return switch (status) {
            case 200 -> "Accessible";
            case 302 -> "Redirect";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            default  -> "Unknown";
        };
    }
}