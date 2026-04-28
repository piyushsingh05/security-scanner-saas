package com.securityscanner.service;

import org.springframework.stereotype.Component;

@Component
public class ScoreCalculator {
    public int calculateScore(
            boolean httpsEnabled,
            boolean xFrame,
            boolean csp,
            boolean hsts
    ) {
        int score = 0;

        if (httpsEnabled) score += 40;
        if (xFrame) score += 20;
        if (csp) score += 20;
        if (hsts) score += 20;

        return score;
    }
}
