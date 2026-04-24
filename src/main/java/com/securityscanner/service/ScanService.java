package com.securityscanner.service;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ScanService {
    private final WebsiteScanRepository _websiteScanRepository;

    public WebsiteScan createScan(ScanRequest request){
        WebsiteScan scan = WebsiteScan.builder()
                .domain(request.getDomain())
                .score(100)
                .status("PENDING")
                .createdAt(LocalDateTime.now())
                .build();
        return _websiteScanRepository.save(scan);
    }
}
