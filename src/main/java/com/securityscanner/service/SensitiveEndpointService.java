package com.securityscanner.service;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Service
public class SensitiveEndpointService {

     public List<String> findExposedEndpoints(String domain) {
        List<String> foundEndpoints = new ArrayList<>();

        try {
            ClassPathResource resource =
                    new ClassPathResource("paths.txt");

            BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(resource.getInputStream())
                    );

            String path;

            while ((path = reader.readLine()) != null) {
                try {
                    URL url = new URL("https://" + domain + path);

                    HttpURLConnection connection =
                            (HttpURLConnection) url.openConnection();

                    connection.setRequestMethod("GET");
                    connection.setConnectTimeout(3000);
                    connection.connect();

                    int responseCode =
                            connection.getResponseCode();

                    if (responseCode == 200) {
                        foundEndpoints.add(path);
                    }

                } catch (Exception e) {
                    // ignore failed path checks
                }
            }

        } catch (Exception e) {
            System.out.println("Failed to read paths.txt");
        }

        return foundEndpoints;
    }
}
