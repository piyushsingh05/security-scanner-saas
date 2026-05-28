package com.securityscanner.controller;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.User;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.UserRepository;
import com.securityscanner.repository.WebsiteScanRepository;
import com.securityscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService  scanService;
    private final UserRepository userRepository;
    private final WebsiteScanRepository   websiteScanRepository; // stats only — acceptable here

    @PostMapping
    public ResponseEntity<WebsiteScan> createScan(
            @Valid @RequestBody ScanRequest request) {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        log.info("[ScanController] POST /api/scan domain={}", request.getDomain());

        WebsiteScan result = scanService.createScan(request,user);


        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public ResponseEntity<List<WebsiteScan>> getHistory() {
        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        String email = authentication.getName();
        List<WebsiteScan> scans = websiteScanRepository.findByUserEmailOrderByCreatedAtDesc(email);
        return ResponseEntity.ok(scans);    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalScans",    websiteScanRepository.countByUserEmail(email));
        stats.put("averageScore",  websiteScanRepository.getAverageScoreByUserEmail(email));
        stats.put("criticalSites", websiteScanRepository.getCriticalSitesByUserEmail(email));
        return ResponseEntity.ok(stats);
    }
}