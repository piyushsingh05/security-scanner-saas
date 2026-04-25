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

    private final PdfReportService _pdfReportService;

    private final HttpsCheckService _httpsCheckService;

    private final HeaderCheckService  _headerCheckService;


    private HttpURLConnection createConnection(String domain) throws Exception {
        URL url = new URL("https://" + domain);

        HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(3000);
        connection.connect();

        return connection;
    }

    public WebsiteScan createScan(ScanRequest request){
        System.out.println("PDF generation started...");
        String domain = request.getDomain();
        boolean httpsEnabled = _httpsCheckService.checkHttps(request.getDomain());
        boolean xFrame =  _headerCheckService.hasHeader(domain, "X-Frame-Options");
        boolean csp =   _headerCheckService.hasHeader(domain, "Content-Security-Policy");
        boolean hsts =  _headerCheckService.hasHeader(domain, "Strict-Transport-Security");
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
        WebsiteScan savedScan = _websiteScanRepository.save(scan);

        _pdfReportService.generateReport(savedScan);

        System.out.println("PDF saved successfully!");

        return savedScan;
    }

}
