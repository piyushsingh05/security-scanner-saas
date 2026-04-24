package com.securityscanner.service;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ScanService {

    private final WebsiteScanRepository _websiteScanRepository;


    private HttpURLConnection createConnection(String domain)
            throws Exception {

        URL url = new URL("https://" + domain);
        HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(3000);
        connection.connect();

        return connection;
    }

    public WebsiteScan createScan(ScanRequest request){
        String domain = request.getDomain();
        boolean httpsEnabled = checkHttps(request.getDomain());
        boolean xFrame = hasHeader(domain, "X-Frame-Options");
        boolean csp = hasHeader(domain, "Content-Security-Policy");
        boolean hsts = hasHeader(domain, "Strict-Transport-Security");
        int score = 0;

        if (httpsEnabled) score += 40;
        if (xFrame) score += 20;
        if (csp) score += 20;
        if (hsts) score += 20;
     //   int score = httpsEnabled ? 90 : 40;
        WebsiteScan scan = WebsiteScan.builder()
                .domain(request.getDomain())
                .httpsEnabled(httpsEnabled)
                .xFrameOptionsEnabled(xFrame)
                .cspEnabled(csp)
                .hstsEnabled(hsts)
                .score(score)
                .status("COMPLETED")
                .createdAt(LocalDateTime.now())
                .build();
        return _websiteScanRepository.save(scan);
    }

    private boolean checkHttps(@NotBlank String domain) {
        try {
            HttpURLConnection connection =
                    createConnection(domain);

            return connection.getResponseCode() == 200;
        }catch (Exception e){
            return false;
        }
    }

    private boolean hasHeader(String domain, String headerName) {
        try{
            HttpURLConnection connection = createConnection(domain);
            return connection.getHeaderField(headerName) != null;
        } catch (Exception e) {
            return false;
        }
    }
}
