package com.securityscanner.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;

@Service
public class HttpsCheckService {

    public HttpURLConnection createConnection(String domain)
            throws Exception {

        URL url = new URL("https://" + domain);

        HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");

        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        return connection;
    }

    public boolean checkHttps(String domain) {

        try {

            HttpURLConnection connection =
                    createConnection(domain);

            connection.connect();

            return connection.getResponseCode() == 200;

        } catch (Exception e) {

            return false;
        }
    }
}