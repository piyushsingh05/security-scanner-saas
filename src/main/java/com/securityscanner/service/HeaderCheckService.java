package com.securityscanner.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Fetches all security-relevant HTTP headers in a single connection.
 * Avoids the overhead of one HTTP call per header check.
 */
@Service
public class HeaderCheckService {

    private static final int TIMEOUT_MS = 5000;

    /**
     * Opens one connection and returns all headers as a map.
     * Returns empty map on failure — callers treat missing = false.
     */
    public Map<String, String> fetchHeaders(String domain) {
        Map<String, String> headers = new HashMap<>();
        HttpURLConnection connection = null;

        try {
            URL url = new URL("https://" + domain);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD"); // HEAD is faster — no body needed
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setInstanceFollowRedirects(true);
            connection.connect();

            // Collect all headers into map (lowercase keys for safe lookup)
            connection.getHeaderFields().forEach((key, values) -> {
                if (key != null && values != null && !values.isEmpty()) {
                    headers.put(key.toLowerCase(), values.get(0));
                }
            });

        } catch (Exception e) {
            // Return empty map — all checks will evaluate to false
        } finally {
            if (connection != null) connection.disconnect();
        }

        return headers;
    }

    public boolean hasHeader(Map<String, String> headers, String headerName) {
        return headers.containsKey(headerName.toLowerCase());
    }
}