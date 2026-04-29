package com.securityscanner.service;

import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Retrieves SSL/TLS certificate details for a given domain.
 * Returns structured plain-text output safe for PDF rendering.
 * Note: All emoji stripped — PDFBox Helvetica cannot encode Unicode symbols.
 */
@Service
public class SSLCheckService {

    private static final int TIMEOUT_MS = 5000;

    public String getSSLDetails(String domain) {  // fixed: was "domian"
        HttpsURLConnection connection = null;
        try {
            URL url = new URL("https://" + domain);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.connect();

            Certificate[] certificates = connection.getServerCertificates();
            if (certificates == null || certificates.length == 0) {
                return "No certificates found";
            }

            X509Certificate cert = (X509Certificate) certificates[0];
            String issuer = cert.getIssuerX500Principal().getName();
            Date expiry = cert.getNotAfter();
            String expiryStr = new SimpleDateFormat("dd MMM yyyy").format(expiry);

            boolean expired = expiry.before(new Date());
            String status = expired ? "EXPIRED" : "Valid";

            // Plain text only — no emoji (PDFBox Helvetica limitation)
            return status + " | Issuer: " + issuer + " | Expiry: " + expiryStr;

        } catch (Exception e) {
            return "SSL check failed: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }
}