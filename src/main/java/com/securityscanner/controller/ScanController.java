package com.securityscanner.controller;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService _scanService;
    @PostMapping
    public WebsiteScan createScan( @RequestBody ScanRequest request){
        System.out.println("DOMAIN = " + request.getDomain());
        return _scanService.createScan(request);
    }
}
