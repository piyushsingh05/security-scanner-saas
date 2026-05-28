package com.securityscanner.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CookieSecurityService {
    private  final HttpsCheckService httpsCheckService;

    public String checkCookieSecurity(String domain){
        try{
            HttpsURLConnection connection = (HttpsURLConnection) httpsCheckService.createConnection(domain);
            connection.connect();
            Map<String, List<String>> headers =
                    connection.getHeaderFields();

            List<String> cookies = headers.get("Set-Cookie");

            if (cookies == null || cookies.isEmpty()) {

                return "INFO: No cookies detected";
            }


            boolean secure = true;
        boolean httpOnly = true;
        boolean sameSite = true;

        for (String cookie : cookies) {

            String lower = cookie.toLowerCase();

            if (!lower.contains("secure")) {
                secure = false;
            }

            if (!lower.contains("httponly")) {
                httpOnly = false;
            }

            if (!lower.contains("samesite")) {
                sameSite = false;
            }
        }

        StringBuilder findings = new StringBuilder();

        if (!secure) {
            findings.append("WARNING: Missing Secure flag | ");
        }

        if (!httpOnly) {
            findings.append("WARNING: Missing HttpOnly flag | ");
        }

        if (!sameSite) {
            findings.append("WARNING: Missing SameSite attribute | ");
        }

        if (findings.isEmpty()) {

            return "SAFE: Cookies properly secured";
        }

        return findings.toString();

    } catch (Exception e) {

        log.warn(
                "[CookieSecurityService] Failed for {} : {}",
                domain,
                e.getMessage()
        );

        return "Cookie security check failed";
    }
    }

}
