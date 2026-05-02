package com.securityscanner.controller;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import com.securityscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService             scanService;
    private final WebsiteScanRepository   websiteScanRepository; // stats only — acceptable here

    @PostMapping
    public ResponseEntity<WebsiteScan> createScan(@Valid @RequestBody ScanRequest request) {
        log.info("[ScanController] POST /api/scan domain={}", request.getDomain());
        WebsiteScan result = scanService.createScan(request);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public ResponseEntity<List<WebsiteScan>> getHistory() {
        return ResponseEntity.ok(websiteScanRepository.findAll(
                Sort.by(Sort.Direction.DESC, "createdAt"))); // ✅ return ALL, not just top 5
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalScans",    websiteScanRepository.getTotalScans());
        stats.put("averageScore",  websiteScanRepository.getAverageScore());
        stats.put("criticalSites", websiteScanRepository.getCriticalSites());
        return ResponseEntity.ok(stats);
    }
}