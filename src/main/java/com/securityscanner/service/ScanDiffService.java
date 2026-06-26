package com.securityscanner.service;

import com.securityscanner.entity.WebsiteScan;
import com.securityscanner.repository.WebsiteScanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ScanDiffService {

    private final WebsiteScanRepository websiteScanRepository;

    public Map<String, Object> diff(String domain, String userEmail) {
        List<WebsiteScan> scans = websiteScanRepository
                .findTop2ByDomainAndUserEmailOrderByCreatedAtDesc(domain, userEmail);

        if (scans.size() < 2) {
            return Map.of("error", "Need at least 2 scans for this domain to compare");
        }

        WebsiteScan current  = scans.get(0);
        WebsiteScan previous = scans.get(1);

        List<Map<String, Object>> changes = new ArrayList<>();

        // Score diff
        int scoreDiff = current.getScore() - previous.getScore();
        changes.add(Map.of(
                "field",    "Security Score",
                "previous", previous.getScore() + "/100",
                "current",  current.getScore()  + "/100",
                "status",   scoreDiff > 0 ? "IMPROVED" : scoreDiff < 0 ? "DEGRADED" : "UNCHANGED",
                "delta",    scoreDiff
        ));

        // HTTPS
        addBooleanDiff(changes, "HTTPS",
                previous.getHttpsEnabled(), current.getHttpsEnabled());

        // X-Frame-Options
        addBooleanDiff(changes, "X-Frame-Options",
                previous.getXFrameOptionsEnabled(), current.getXFrameOptionsEnabled());

        // CSP
        addBooleanDiff(changes, "Content-Security-Policy",
                previous.getCspEnabled(), current.getCspEnabled());

        // HSTS
        addBooleanDiff(changes, "HSTS",
                previous.getHstsEnabled(), current.getHstsEnabled());

        // Open Ports
        addStringDiff(changes, "Open Ports",
                previous.getOpenPorts(), current.getOpenPorts());

        // Directory Findings
        addStringDiff(changes, "Exposed Directories",
                previous.getDirectoryFindings(), current.getDirectoryFindings());

        // Leaked Secrets
        addStringDiff(changes, "Leaked Secrets",
                previous.getLeakedSecrets(), current.getLeakedSecrets());

        // CORS
        addStringDiff(changes, "CORS Findings",
                previous.getCorsFindings(), current.getCorsFindings());

        return Map.of(
                "domain",       domain,
                "previousDate", previous.getCreatedAt().toString(),
                "currentDate",  current.getCreatedAt().toString(),
                "previousScore", previous.getScore(),
                "currentScore",  current.getScore(),
                "scoreDelta",    scoreDiff,
                "changes",       changes
        );
    }

    private void addBooleanDiff(List<Map<String, Object>> changes,
                                String field,
                                Boolean prev, Boolean curr) {
        String prevStr = Boolean.TRUE.equals(prev) ? "ENABLED" : "MISSING";
        String currStr = Boolean.TRUE.equals(curr) ? "ENABLED" : "MISSING";
        String status;
        if (Objects.equals(prev, curr))          status = "UNCHANGED";
        else if (Boolean.TRUE.equals(curr))      status = "IMPROVED";
        else                                      status = "DEGRADED";

        changes.add(Map.of(
                "field",    field,
                "previous", prevStr,
                "current",  currStr,
                "status",   status,
                "delta",    0
        ));
    }

    private void addStringDiff(List<Map<String, Object>> changes,
                               String field,
                               String prev, String curr) {
        String prevStr = (prev == null || prev.isBlank()) ? "None" : prev;
        String currStr = (curr == null || curr.isBlank()) ? "None" : curr;
        if (prevStr.equals(currStr)) return; // skip unchanged string fields

        boolean wasClean = prevStr.equals("None");
        boolean isClean  = currStr.equals("None");
        String status = isClean ? "IMPROVED" : wasClean ? "DEGRADED" : "CHANGED";

        changes.add(Map.of(
                "field",    field,
                "previous", prevStr,
                "current",  currStr,
                "status",   status,
                "delta",    0
        ));
    }
}