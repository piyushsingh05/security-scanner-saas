package com.securityscanner.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;

@Slf4j
@Service
@RequiredArgsConstructor
public class CorsCheckService {

    private final HttpsCheckService httpsCheckService;

    public String checkCors(String domain) {

        try {

            HttpURLConnection connection =
                    httpsCheckService.createConnection(domain);

            connection.connect();

            String allowOrigin =
                    connection.getHeaderField(
                            "Access-Control-Allow-Origin"
                    );

            String allowCredentials =
                    connection.getHeaderField(
                            "Access-Control-Allow-Credentials"
                    );

            if ("*".equals(allowOrigin)
                    && "true".equalsIgnoreCase(allowCredentials)) {

                return "CRITICAL: Wildcard origin with credentials enabled";
            }

            if ("*".equals(allowOrigin)) {

                return "WARNING: Wildcard CORS enabled";
            }

            if (allowOrigin != null && !allowOrigin.isBlank()) {

                return "SAFE: CORS restricted to " + allowOrigin;
            }

            return "INFO: No CORS headers detected";

        } catch (Exception e) {

            log.warn(
                    "[CorsCheckService] Failed for {} : {}",
                    domain,
                    e.getMessage()
            );

            return "CORS check failed";
        }
    }
}