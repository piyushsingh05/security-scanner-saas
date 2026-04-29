package com.securityscanner.service;

import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Calculates a security score out of 100.
 *
 * Weights:
 *   HTTPS              40 pts  (foundational — no HTTPS = high risk)
 *   X-Frame-Options    15 pts
 *   CSP                25 pts  (most complex to implement, worth more)
 *   HSTS               20 pts
 *
 * Total: 100 pts
 */
@Component
public class ScoreCalculator {

    public int calculateScore(
            boolean httpsEnabled,
            boolean xFrameEnabled,
            boolean cspEnabled,
            boolean hstsEnabled
    ) {
        int score = 0;

        if (httpsEnabled)   score += 40;
        if (xFrameEnabled)  score += 15;
        if (cspEnabled)     score += 25;
        if (hstsEnabled)    score += 20;

        return Math.min(score, 100); // safety cap
    }

    public String calculateGrade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 50) return "C";
        return "D";
    }

    public String getRiskLevel(int score) {
        if (score >= 90) return "Low Risk";
        if (score >= 75) return "Moderate";
        if (score >= 50) return "Needs Improvement";
        return "High Risk";
    }
}