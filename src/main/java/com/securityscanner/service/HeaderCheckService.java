package com.securityscanner.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;

@Service
public class HeaderCheckService {

    private HttpURLConnection createConnection(String domain) throws Exception {
        URL url = new URL("https://" + domain);

        HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(3000);
        connection.connect();

        return connection;
    }


    public boolean hasHeader(String domain, String headerName) {
        try {
            HttpURLConnection connection =
                    createConnection(domain);

            return connection.getHeaderField(headerName) != null;

        } catch (Exception e) {
            return false;
        }
    }
}
