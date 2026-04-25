package com.securityscanner.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;

@Service
public class HttpsCheckService {
    public boolean checkHttps(String domain) {
        try {
            URL url = new URL("https://" + domain);

            HttpURLConnection connection =
                    (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.connect();

            return connection.getResponseCode() == 200;

        } catch (Exception e) {
            return false;
        }
    }
}
