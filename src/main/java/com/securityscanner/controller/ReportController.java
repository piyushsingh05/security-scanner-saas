package com.securityscanner.controller;

import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import com.securityscanner.service.PdfReportService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * Generates PDF on-demand rather than reading from disk.
 * Disk-based PDFs are lost on every Render.com/cloud deploy.
 * Generating in memory is stateless and deploy-safe.
 */
@Slf4j
@RestController
@RequestMapping("/api/report")
@RequiredArgsConstructor
public class ReportController {

    private final WebsiteScanRepository websiteScanRepository;
    private final PdfReportService      pdfReportService;

    @GetMapping("/{id}")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long id) {
        WebsiteScan scan = websiteScanRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Scan not found: " + id));

        try {
            byte[] pdfBytes = pdfReportService.generateReportBytes(scan);

            String filename = "securiscan_report_" + scan.getDomain() + ".pdf";

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .contentLength(pdfBytes.length)
                    .body(pdfBytes);

        } catch (IOException e) {
            log.error("[ReportController] PDF generation failed for id={}: {}", id, e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}