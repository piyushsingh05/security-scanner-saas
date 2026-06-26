package com.securityscanner.service;

import com.securityscanner.entity.Domain;
import com.securityscanner.entity.WebsiteScan;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AlertService {

    private final EmailService emailService;

    private static final int SCORE_DROP_THRESHOLD = 10;

    /**
     * Compares previous scan vs new scan.
     * Fires alert email if:
     *   - score dropped by 10+ points
     *   - new critical issue appeared (HTTPS lost, secrets leaked, etc.)
     *   - SSL expiry warning detected
     */
    public void evaluateAndAlert(Domain domain,
                                 WebsiteScan previous,
                                 WebsiteScan current) {

        if (!Boolean.TRUE.equals(domain.getEmailAlertsEnabled())) return;

        String email = domain.getUser().getEmail();
        List<String> changes = new ArrayList<>();

        int oldScore = previous != null ? previous.getScore() : current.getScore();
        int newScore = current.getScore();

        // Score drop check
        if (previous != null && (oldScore - newScore) >= SCORE_DROP_THRESHOLD) {
            changes.add("Score dropped " + oldScore + " → " + newScore);
        }

        // HTTPS lost
        if (previous != null
                && Boolean.TRUE.equals(previous.getHttpsEnabled())
                && Boolean.FALSE.equals(current.getHttpsEnabled())) {
            changes.add("CRITICAL: HTTPS is no longer enabled");
        }

        // New secrets leaked
        if (current.getLeakedSecrets() != null
                && !current.getLeakedSecrets().isBlank()
                && (previous == null || previous.getLeakedSecrets() == null
                || previous.getLeakedSecrets().isBlank())) {
            changes.add("CRITICAL: Secrets/credentials detected in page source");
        }

        // New open ports appeared
        if (current.getOpenPorts() != null && !current.getOpenPorts().isBlank()
                && (previous == null || previous.getOpenPorts() == null
                || previous.getOpenPorts().isBlank())) {
            changes.add("New open ports detected: " + current.getOpenPorts());
        }

        // New exposed directories
        if (current.getDirectoryFindings() != null
                && !current.getDirectoryFindings().isBlank()
                && (previous == null || previous.getDirectoryFindings() == null
                || previous.getDirectoryFindings().isBlank())) {
            changes.add("Exposed directories found: " + current.getDirectoryFindings());
        }

        // SSL expiry warning (simple string check)
        if (current.getSslDetails() != null
                && (current.getSslDetails().contains("expir")
                || current.getSslDetails().contains("EXPIR"))) {
            emailService.sendSslExpiryAlert(email,
                    domain.getDomain(), current.getSslDetails());
        }

        // Send alert if changes detected
        if (!changes.isEmpty()) {
            String summary = String.join(" | ", changes);
            log.info("[AlertService] Alert triggered for {} — {}", domain.getDomain(), summary);
            emailService.sendAlertEmail(email, domain.getDomain(),
                    oldScore, newScore, summary);
        } else {
            log.info("[AlertService] No significant changes for {}", domain.getDomain());
        }
    }
}