package com.securityscanner.controller;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import com.securityscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService _scanService;

    private final WebsiteScanRepository _websiteScanRepository;
    @PostMapping
    public WebsiteScan createScan( @Valid @RequestBody ScanRequest request){
        System.out.println("DOMAIN = " + request.getDomain());
        return _scanService.createScan(request);
    }

    @GetMapping("/history")
    public List<WebsiteScan> getHistory(){
        return _scanService.getRecentScan();
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("totalScans",
                _websiteScanRepository.getTotalScans());

        stats.put("averageScore",
                _websiteScanRepository.getAverageScore());

        stats.put("criticalSites",
                _websiteScanRepository.getCriticalSites());

        return stats;
    }
}
