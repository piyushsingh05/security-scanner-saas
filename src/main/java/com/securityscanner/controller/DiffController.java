package com.securityscanner.controller;

import com.securityscanner.service.ScanDiffService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class DiffController {

    private final ScanDiffService scanDiffService;

    @GetMapping("/diff")
    public ResponseEntity<Map<String, Object>> getDiff(
            @RequestParam String domain) {

        String email = SecurityContextHolder.getContext()
                .getAuthentication().getName();

        return ResponseEntity.ok(scanDiffService.diff(domain, email));
    }
}