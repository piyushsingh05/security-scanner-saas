package com.securityscanner.service;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final WebsiteScanRepository    websiteScanRepository;
    private final PdfReportService         pdfReportService;
    private final HttpsCheckService        httpsCheckService;
    private final HeaderCheckService       headerCheckService;
    private final ScoreCalculator          scoreCalculator;
    private final SensitiveEndpointService sensitiveEndpointService;
    private final SSLCheckService          sslCheckService;
    private final OpenPortScanService      openPortScanService;
    private final SecretLeakScannerService secretLeakScannerService;

    public WebsiteScan createScan(ScanRequest request) {
        String domain = request.getDomain().trim();
        log.info("[ScanService] Starting parallel scan for: {}", domain);

        long start = System.currentTimeMillis();

        // Fire ALL checks at the same time
        CompletableFuture<Boolean> httpsFuture =
                CompletableFuture.supplyAsync(() -> httpsCheckService.checkHttps(domain));

        CompletableFuture<Map<String, String>> headersFuture =
                CompletableFuture.supplyAsync(() -> headerCheckService.fetchHeaders(domain));

        CompletableFuture<String> sslFuture =
                CompletableFuture.supplyAsync(() -> sslCheckService.getSSLDetails(domain));

        CompletableFuture<List<String>> endpointsFuture =
                CompletableFuture.supplyAsync(() -> sensitiveEndpointService.findExposedEndpoints(domain));

        CompletableFuture<List<String>> openPortsFuture =
                CompletableFuture.supplyAsync(() -> openPortScanService.scanOpenPorts(domain));

        CompletableFuture<List<SecretLeakScannerService.LeakFinding>> leaksFuture =
                CompletableFuture.supplyAsync(() -> secretLeakScannerService.scanForLeaks(domain));

        // Wait for all to complete (max 25 seconds total)
        CompletableFuture.allOf(httpsFuture, headersFuture, sslFuture, endpointsFuture , openPortsFuture , leaksFuture)
                .orTimeout(25, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    log.warn("[ScanService] Some checks timed out for {}: {}", domain, ex.getMessage());
                    return null;
                })
                .join();


        // Collect results — safe defaults if a future failed/timed out
        boolean httpsEnabled = getFutureSafe(httpsFuture, false);
        Map<String, String> headers = getFutureSafe(headersFuture, Map.of());
        String sslDetails = getFutureSafe(sslFuture, "SSL check timed out");
        List<String> exposedList = getFutureSafe(endpointsFuture, List.of());

        List<String> openPortsList =
                getFutureSafe(openPortsFuture, List.of());

        String openPorts =
                openPortsList.isEmpty()
                        ? null
                        : String.join(", ", openPortsList);

        List<SecretLeakScannerService.LeakFinding> leakFindings =
                getFutureSafe(leaksFuture, List.of());

        String leakedSecrets = leakFindings.isEmpty()
                ? null
                : leakFindings.stream()
                .map(Object::toString)
                .reduce((a, b) -> a + ", " + b)
                .orElse(null);

        boolean xFrame = headerCheckService.hasHeader(headers, "X-Frame-Options");
        boolean csp    = headerCheckService.hasHeader(headers, "Content-Security-Policy");
        boolean hsts   = headerCheckService.hasHeader(headers, "Strict-Transport-Security");

        int    score     = scoreCalculator.calculateScore(httpsEnabled, xFrame, csp, hsts);
        String endpoints = exposedList.isEmpty() ? null : String.join(", ", exposedList);

        long elapsed = System.currentTimeMillis() - start;
        log.info("[ScanService] Done in {}ms | domain={} score={} endpoints={}",
                elapsed, domain, score, endpoints);

        WebsiteScan scan = WebsiteScan.builder()
                .domain(domain)
                .httpsEnabled(httpsEnabled)
                .xFrameOptionsEnabled(xFrame)
                .cspEnabled(csp)
                .hstsEnabled(hsts)
                .score(score)
                .status("COMPLETED")
                .sslDetails(sslDetails)
                .exposedEndpoints(endpoints)
                .openPorts(openPorts)
                .leakedSecrets(leakedSecrets)
                .createdAt(LocalDateTime.now())
                .build();

        WebsiteScan savedScan = websiteScanRepository.save(scan);

        // PDF runs in background — user gets response immediately
        CompletableFuture.runAsync(() -> {
            try {
                pdfReportService.generateReport(savedScan);
                log.info("[ScanService] PDF ready for scan id={}", savedScan.getId());
            } catch (Exception e) {
                log.error("[ScanService] PDF failed for id={}: {}", savedScan.getId(), e.getMessage());
            }
        });

        return savedScan;
    }

    public List<WebsiteScan> getRecentScan() {
        return websiteScanRepository.findTop5ByOrderByCreatedAtDesc();
    }

    private <T> T getFutureSafe(CompletableFuture<T> future, T fallback) {
        try {
            return future.getNow(fallback);
        } catch (Exception e) {
            return fallback;
        }
    }
}