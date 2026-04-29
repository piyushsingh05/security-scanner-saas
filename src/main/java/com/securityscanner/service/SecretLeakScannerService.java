package com.securityscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Scans for leaked secrets by:
 * 1. Checking if sensitive files are accessible
 * 2. Reading the response body and detecting real secret patterns
 *
 * This is more valuable than just checking HTTP status codes —
 * a /.env returning 200 with "DB_PASSWORD=secret" is a critical finding.
 */
@Slf4j
@Service
public class SecretLeakScannerService {

    private static final int TIMEOUT_MS      = 4000;
    private static final int MAX_BODY_CHARS  = 3000; // read only first 3KB

    // Files to check — these should NOT be in paths.txt to avoid duplication
    private static final String[] SECRET_PATHS = {
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.git/config",
            "/.git/HEAD",
            "/config.json",
            "/application.properties",
            "/application.yml",
            "/backup.sql",
            "/dump.sql",
            "/database.env",
            "/secrets.json",
            "/credentials.json",
            "/.aws/credentials",
            "/wp-config.php",
            "/config.php"
    };

    // Regex patterns that indicate real secrets in response body
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("(?i)(password|passwd|pwd)\\s*[=:]\\s*\\S+"),
            Pattern.compile("(?i)(api[_-]?key|apikey)\\s*[=:]\\s*\\S+"),
            Pattern.compile("(?i)(secret[_-]?key|secret)\\s*[=:]\\s*\\S+"),
            Pattern.compile("(?i)(access[_-]?token|auth[_-]?token)\\s*[=:]\\s*\\S+"),
            Pattern.compile("(?i)(db[_-]?password|database[_-]?password)\\s*[=:]\\s*\\S+"),
            Pattern.compile("(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)\\s*[=:]\\s*\\S+"),
            Pattern.compile("AKIA[0-9A-Z]{16}"),                          // AWS key format
            Pattern.compile("(?i)\\[core\\]"),                            // .git/config marker
            Pattern.compile("(?i)(private[_-]?key|rsa[_-]?key)"),
            Pattern.compile("(?i)DB_HOST\\s*="),                          // .env marker
            Pattern.compile("(?i)mysql://|postgresql://|mongodb://")      // DB connection strings
    );

    public List<LeakFinding> scanForLeaks(String domain) {
        log.info("[SecretLeakScanner] Starting for: {}", domain);
        List<LeakFinding> findings = new ArrayList<>();

        for (String path : SECRET_PATHS) {
            LeakFinding finding = checkSecretFile(domain, path);
            if (finding != null) {
                findings.add(finding);
                log.warn("[SecretLeakScanner] LEAK FOUND: {} | severity={} | reason={}",
                        path, finding.getSeverity(), finding.getReason());
            }
        }

        log.info("[SecretLeakScanner] Done | domain={} | findings={}", domain, findings.size());
        return findings;
    }

    private LeakFinding checkSecretFile(String domain, String path) {
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

            if (code == 200) {
                // File is accessible — now read body to detect actual secrets
                String body = readBody(connection);
                String matchedPattern = detectSecretInBody(body);

                if (matchedPattern != null) {
                    // Critical — file is accessible AND contains real secrets
                    return new LeakFinding(path, "CRITICAL",
                            "File accessible and contains secret pattern: " + matchedPattern);
                } else {
                    // File is accessible but no obvious secrets detected
                    return new LeakFinding(path, "HIGH",
                            "Sensitive file is publicly accessible (200 OK)");
                }

            } else if (code == 403) {
                // File exists but access denied — still worth flagging
                return new LeakFinding(path, "LOW",
                        "File exists but access is restricted (403 Forbidden)");
            }

        } catch (Exception ignored) {
        } finally {
            if (connection != null) connection.disconnect();
        }

        return null;
    }

    private String readBody(HttpURLConnection connection) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {

            StringBuilder sb = new StringBuilder();
            char[] buf = new char[MAX_BODY_CHARS];
            int read = reader.read(buf, 0, MAX_BODY_CHARS);
            if (read > 0) sb.append(buf, 0, read);
            return sb.toString();

        } catch (Exception e) {
            return "";
        }
    }

    private String detectSecretInBody(String body) {
        if (body == null || body.isBlank()) return null;

        for (Pattern pattern : SECRET_PATTERNS) {
            var matcher = pattern.matcher(body);
            if (matcher.find()) {
                return pattern.pattern(); // return which pattern matched
            }
        }
        return null;
    }

    // ── Inner result class ──────────────────────────────────────────────────
    public static class LeakFinding {
        private final String path;
        private final String severity;  // CRITICAL, HIGH, LOW
        private final String reason;

        public LeakFinding(String path, String severity, String reason) {
            this.path = path;
            this.severity = severity;
            this.reason = reason;
        }

        public String getPath()     { return path; }
        public String getSeverity() { return severity; }
        public String getReason()   { return reason; }

        @Override
        public String toString() {
            return "[" + severity + "] " + path + " — " + reason;
        }
    }
}