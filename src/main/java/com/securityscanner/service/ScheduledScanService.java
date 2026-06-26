package com.securityscanner.service;

import com.securityscanner.dto.ScanRequest;
import com.securityscanner.entity.Domain;
import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.DomainRepository;
import com.securityscanner.repository.WebsiteScanRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScheduledScanService {

    private final DomainRepository       domainRepository;
    private final WebsiteScanRepository  websiteScanRepository;
    private final ScanService            scanService;
    private final AlertService           alertService;

    /**
     * Runs every hour.
     * Picks up domains whose next scan is due based on their frequency.
     */
    @Scheduled(fixedDelay = 60 * 60 * 1000) // every hour
    public void runDueScans() {
        log.info("[Scheduler] Checking for due domain scans...");

        List<Domain> allDomains = domainRepository.findAll();
        int triggered = 0;

        for (Domain domain : allDomains) {
            if (isDue(domain)) {
                log.info("[Scheduler] Domain due: {}", domain.getDomain());
                try {
                    scanDomain(domain);
                    triggered++;
                } catch (Exception e) {
                    log.error("[Scheduler] Failed to scan {}: {}",
                            domain.getDomain(), e.getMessage());
                }
            }
        }

        log.info("[Scheduler] Done. {} domain(s) scanned.", triggered);
    }

    private void scanDomain(Domain domain) {
        // Get the previous scan for comparison
        WebsiteScan previous = websiteScanRepository
                .findTopByDomainAndUserEmailOrderByCreatedAtDesc(
                        domain.getDomain(),
                        domain.getUser().getEmail())
                .orElse(null);

        // Run the scan
        ScanRequest req = new ScanRequest();
        req.setDomain(domain.getDomain());
        WebsiteScan current = scanService.createScan(req, domain.getUser());

        // Evaluate and fire alerts if needed
        alertService.evaluateAndAlert(domain, previous, current);
    }

    private boolean isDue(Domain domain) {
        if (domain.getLastScannedAt() == null) return true; // never scanned

        Domain.ScanFrequency frequency = domain.getScanFrequency();

        if (frequency == null) {
            frequency = Domain.ScanFrequency.WEEKLY;
        }

        LocalDateTime now  = LocalDateTime.now();
        LocalDateTime last = domain.getLastScannedAt();

        return switch (frequency) {
            case DAILY   -> last.isBefore(now.minusHours(24));
            case WEEKLY  -> last.isBefore(now.minusDays(7));
            case MONTHLY -> last.isBefore(now.minusDays(30));
        };
    }
}
