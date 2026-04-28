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
import java.util.List;

@Service
@RequiredArgsConstructor
public class ScanService {

    private final WebsiteScanRepository _websiteScanRepository;

    private final PdfReportService _pdfReportService;

    private final HttpsCheckService _httpsCheckService;

    private final HeaderCheckService  _headerCheckService;

    private final ScoreCalculator _scoreCalculator;

    private final SensitiveEndpointService _sensitiveEndpointService;

    public WebsiteScan createScan(ScanRequest request){
        String domain = request.getDomain();

        List<String> exposedEndpoints =
                _sensitiveEndpointService.findExposedEndpoints(domain);

        System.out.println("Exposed Endpoints: " + exposedEndpoints);
        boolean httpsEnabled = _httpsCheckService.checkHttps(request.getDomain());
        boolean xFrame =  _headerCheckService.hasHeader(domain, "X-Frame-Options");
        boolean csp =   _headerCheckService.hasHeader(domain, "Content-Security-Policy");
        boolean hsts =  _headerCheckService.hasHeader(domain, "Strict-Transport-Security");
        int score = _scoreCalculator.calculateScore(httpsEnabled, xFrame, csp, hsts);
        String endpoints =
                String.join(", ", exposedEndpoints);
     //   int score = httpsEnabled ? 90 : 40;
        WebsiteScan scan = WebsiteScan.builder()
                .domain(request.getDomain())
                .httpsEnabled(httpsEnabled)
                .xFrameOptionsEnabled(xFrame)
                .cspEnabled(csp)
                .hstsEnabled(hsts)
                .score(score)
                .status("COMPLETED")
                .exposedEndpoints(endpoints)
                .createdAt(LocalDateTime.now())
                .build();
        WebsiteScan savedScan = _websiteScanRepository.save(scan);

        _pdfReportService.generateReport(savedScan);

        System.out.println("PDF saved successfully!");

        return savedScan;
    }


    public List<WebsiteScan> getRecentScan() {
        return _websiteScanRepository.findTop5ByOrderByCreatedAtDesc();
    }
}
