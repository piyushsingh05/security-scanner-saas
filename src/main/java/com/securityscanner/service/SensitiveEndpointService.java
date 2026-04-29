package com.securityscanner.service;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Service
public class SensitiveEndpointService {

    private static final int TIMEOUT_MS   = 3000;
    private static final int THREAD_POOL  = 10;
    private static final int MAX_WAIT_SEC = 20;

    public List<String> findExposedEndpoints(String domain) {
        List<String> paths = loadPaths();
        if (paths.isEmpty()) {
            System.err.println("[SensitiveEndpointService] No paths loaded from paths.txt");
            return List.of();
        }

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL);
        List<Future<String>> futures = new ArrayList<>();

        for (String path : paths) {
            futures.add(executor.submit(() -> checkPath(domain, path)));
        }

        executor.shutdown();

        List<String> exposed = new ArrayList<>();
        try {
            executor.awaitTermination(MAX_WAIT_SEC, TimeUnit.SECONDS);

            for (Future<String> future : futures) {
                if (future.isDone()) {
                    try {
                        String result = future.get();
                        if (result != null) exposed.add(result);
                    } catch (ExecutionException e) {
                        // skip failed checks
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[SensitiveEndpointService] Found " + exposed.size() + " endpoints: " + exposed);
        return exposed;
    }

    private String checkPath(String domain, String path) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://" + domain + path);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.connect();

            int code = connection.getResponseCode();
            System.out.println("[Endpoints] " + path + " -> " + code);

            // 200 = endpoint exists
            // 301/302 = redirects (e.g. /robots.txt redirecting to https still means it exists)
            // 403 = forbidden but exists (e.g. /admin blocked but real)
            return (code == 200 || code == 302 || code == 403) ? path : null;

        } catch (Exception e) {
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private List<String> loadPaths() {
        try {
            ClassPathResource resource = new ClassPathResource("paths.txt");
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream())
            );
            List<String> paths = reader.lines()
                    .map(String::trim)
                    .map(line -> line.replace("\r", ""))
                    .filter(line -> !line.isEmpty() && line.startsWith("/"))
                    .collect(Collectors.toList());

            System.out.println("[SensitiveEndpointService] Loaded " + paths.size() + " paths: " + paths);
            return paths;
        } catch (Exception e) {
            System.err.println("[SensitiveEndpointService] Failed to load paths.txt: " + e.getMessage());
            return List.of();
        }
    }
}