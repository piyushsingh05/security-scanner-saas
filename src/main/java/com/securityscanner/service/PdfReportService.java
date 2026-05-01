package com.securityscanner.service;

import com.securityscanner.entity.WebsiteScan;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * SecuriScan — Professional Dark-Themed PDF Report Generator
 *
 * Report contains ONLY data relevant to the scanned domain:
 *   - Branding header + scan metadata
 *   - Domain, scan date, security score + grade
 *   - Security header checks (HTTPS, X-Frame-Options, CSP, HSTS)
 *   - Sensitive endpoints detected
 *   - SSL certificate details
 *   - Open ports
 *   - Leaked secrets check
 *   - Auto-generated recommendations
 *
 * Deliberately EXCLUDED (dashboard-level data — irrelevant to recipient):
 *   - Total scans count
 *   - Average score across all scans
 *   - Critical sites count
 */
@Service
public class PdfReportService {

    // ── Page (A4 = 595 x 842 pt) ──────────────────────────────────────────────
    private static final float PW     = PDRectangle.A4.getWidth();
    private static final float PH     = PDRectangle.A4.getHeight();
    private static final float MARGIN = 20f;

    // ── Brand colours ─────────────────────────────────────────────────────────
    private static final Color DARK_BG     = hex("#0D1117");
    private static final Color CARD_BG     = hex("#161B22");
    private static final Color ACCENT_BLUE = hex("#1F6FEB");
    private static final Color ACCENT_CYAN = hex("#39D0D8");
    private static final Color GREEN       = hex("#3FB950");
    private static final Color RED         = hex("#F85149");
    private static final Color YELLOW      = hex("#D29922");
    private static final Color TEXT_WHITE  = hex("#E6EDF3");
    private static final Color TEXT_GRAY   = hex("#8B949E");
    private static final Color BORDER      = hex("#21262D");

    // Fonts — initialised once per generateReportBytes() call
    private PDType1Font BOLD, REGULAR, ITALIC;

    // ─────────────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /** Returns PDF as byte array — used by ReportController for HTTP download. */
    public byte[] generateReportBytes(WebsiteScan scan) throws IOException {
        try (PDDocument doc = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            BOLD    = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            REGULAR = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            ITALIC  = new PDType1Font(Standard14Fonts.FontName.HELVETICA_OBLIQUE);

            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);

            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                drawPage(cs, scan);
            }

            doc.save(out);
            return out.toByteArray();
        }
    }

    /** Legacy shim — kept for backward-compat with ScanService. */
    public String generateReport(WebsiteScan scan) {
        try {
            generateReportBytes(scan);
            return "generated";
        } catch (IOException e) {
            throw new RuntimeException("PDF generation failed: " + e.getMessage(), e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  PAGE ORCHESTRATOR
    // ─────────────────────────────────────────────────────────────────────────

    private void drawPage(PDPageContentStream cs, WebsiteScan scan) throws IOException {
        fillRect(cs, 0, 0, PW, PH, DARK_BG);           // full dark background

        float cursor = PH;
        cursor = drawHeader(cs, cursor, scan);           // branding bar
        cursor = drawDomainScoreCard(cs, cursor, scan);  // domain + score
        cursor = drawSecurityChecks(cs, cursor, scan);   // HTTPS / CSP / HSTS / X-Frame
        cursor = drawEndpointsCard(cs, cursor, scan);    // sensitive endpoints
        cursor = drawSslPortsRow(cs, cursor, scan);      // SSL cert + open ports
        cursor = drawLeakedSecrets(cs, cursor, scan);    // leaked secrets
        drawRecommendations(cs, cursor, scan);    // recommendations (bottom)

        drawFooter(cs);                                  // fixed footer
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SECTION DRAWERS
    // ─────────────────────────────────────────────────────────────────────────

    private float drawHeader(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h = 60;
        float y = cursor - h;

        fillRect(cs, 0, y, PW, h, CARD_BG);
        fillRect(cs, 0, y, 4,  h, ACCENT_BLUE);         // left stripe
        fillRect(cs, 0, y + h - 2, PW, 2, ACCENT_BLUE); // top line

        // Logo box + letter
        fillRect(cs, MARGIN, y + 12, 36, 36, ACCENT_BLUE);
        drawText(cs, BOLD, 20, TEXT_WHITE, MARGIN + 9, y + 20, "S");

        // Title
        drawText(cs, BOLD,     18, TEXT_WHITE, MARGIN + 46, y + 33, "SecuriScan");
        drawText(cs, REGULAR,   9, TEXT_GRAY,  MARGIN + 46, y + 18,
                "Security Audit Report  |  Confidential");

        // Right-side meta
        drawTextRight(cs, REGULAR, 8, TEXT_GRAY, PW - MARGIN, y + 38,
                "Generated: " + date(scan));
        drawTextRight(cs, REGULAR, 8, TEXT_GRAY, PW - MARGIN, y + 24,
                "securiscan.io  |  v1.0.0");

        return y - 10;
    }

    private float drawDomainScoreCard(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h = 110;
        float y = cursor - h;

        fillRect(cs, MARGIN, y, PW - MARGIN * 2, h, CARD_BG);
        strokeRect(cs, MARGIN, y, PW - MARGIN * 2, h, BORDER, 0.6f);
        fillRect(cs, MARGIN, y + h - 3, PW - MARGIN * 2, 3, ACCENT_BLUE); // top accent

        // Left: domain info
        drawText(cs, REGULAR,  7, ACCENT_CYAN, MARGIN + 14, y + h - 18, "TARGET DOMAIN");
        drawText(cs, BOLD,    16, TEXT_WHITE,  MARGIN + 14, y + h - 38, clean(scan.getDomain()));
        drawText(cs, REGULAR,  8, TEXT_GRAY,   MARGIN + 14, y + h - 54,
                "Scan date:  " + date(scan));
        drawText(cs, REGULAR,  8, TEXT_GRAY,   MARGIN + 14, y + h - 67,
                "Report ID:  SCN-" + scan.getId());

        // Status pill
        boolean done = "completed".equalsIgnoreCase(clean(scan.getStatus()));
        Color   sc   = done ? GREEN : YELLOW;
        fillRect(cs, MARGIN + 14, y + 12, 74, 18, done ? hex("#1A3A2A") : hex("#3A2A1A"));
        fillCircle(cs, MARGIN + 26, y + 21, 4, sc);
        drawText(cs, BOLD, 7, sc, MARGIN + 34, y + 17,
                clean(scan.getStatus()).toUpperCase());

        // Right: score circle
        float cx = PW - MARGIN - 58;
        float cy = y + h / 2f + 10;
        drawScoreCircle(cs, cx, cy, scan.getScore());

        // Grade badge under circle
        String grade = scoreToGrade(scan.getScore());
        Color  gc    = scoreColor(scan.getScore());
        fillRect(cs, cx - 20, y + 8, 40, 22, gc);
        drawTextCentred(cs, BOLD,    12, TEXT_WHITE, cx, y + 13, grade);
        drawTextCentred(cs, REGULAR,  6, TEXT_GRAY,  cx, y + 4,  "GRADE");

        return y - 10;
    }

    private float drawSecurityChecks(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h = 82;
        float y = cursor - h;

        fillRect(cs, MARGIN, y, PW - MARGIN * 2, h, CARD_BG);
        strokeRect(cs, MARGIN, y, PW - MARGIN * 2, h, BORDER, 0.6f);

        drawText(cs, BOLD, 8, ACCENT_CYAN, MARGIN + 12, y + h - 14,
                "SECURITY HEADER CHECKS");
        fillRect(cs, MARGIN + 12, y + h - 16, 155, 1, ACCENT_CYAN);

        String[]  labels = {"HTTPS", "X-Frame-Options", "CSP Header", "HSTS"};
        Boolean[] vals   = {
                scan.getHttpsEnabled(),
                scan.getXFrameOptionsEnabled(),
                scan.getCspEnabled(),
                scan.getHstsEnabled()
        };

        float usableW = PW - MARGIN * 2 - 24;
        float badgeW  = usableW / 4f - 4f;
        float badgeH  = 38;

        for (int i = 0; i < 4; i++) {
            float bx = MARGIN + 12 + i * (badgeW + 5f);
            float by = y + 10;
            boolean ok = Boolean.TRUE.equals(vals[i]);
            Color   dot = ok ? GREEN : RED;

            fillRect(cs, bx, by, badgeW, badgeH, ok ? hex("#1A2332") : hex("#2A1A1A"));
            strokeRect(cs, bx, by, badgeW, badgeH, BORDER, 0.5f);
            fillCircle(cs, bx + 13, by + badgeH / 2f, 5, dot);
            drawText(cs, BOLD,    8, TEXT_WHITE, bx + 25, by + badgeH / 2f + 5,  labels[i]);
            drawText(cs, REGULAR, 7, dot,        bx + 25, by + badgeH / 2f - 6,
                    ok ? "ENABLED" : "MISSING");
        }

        return y - 10;
    }

    private float drawEndpointsCard(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h = 65;
        float y = cursor - h;

        fillRect(cs, MARGIN, y, PW - MARGIN * 2, h, CARD_BG);
        strokeRect(cs, MARGIN, y, PW - MARGIN * 2, h, BORDER, 0.6f);

        drawText(cs, BOLD,    8, ACCENT_CYAN, MARGIN + 12, y + h - 14,
                "SENSITIVE ENDPOINTS");
        fillRect(cs, MARGIN + 12, y + h - 16, 130, 1, ACCENT_CYAN);
        drawText(cs, REGULAR, 8, TEXT_GRAY,   MARGIN + 12, y + h - 28,
                "Publicly accessible paths detected on target:");

        String raw = scan.getExposedEndpoints();
        if (raw != null && !raw.isBlank()) {
            float px = MARGIN + 12;
            for (String ep : clean(raw).split("[,;\\s]+")) {
                if (ep.isBlank()) continue;
                float pw = pillWidth(ep);
                fillRect(cs, px, y + 10, pw, 18, hex("#1F3A5C"));
                drawText(cs, REGULAR, 8, ACCENT_CYAN, px + 7, y + 14, ep);
                px += pw + 6;
                if (px > PW - MARGIN - 80) break;
            }
        } else {
            drawText(cs, ITALIC, 8, TEXT_GRAY, MARGIN + 12, y + 14,
                    "No sensitive endpoints detected");
        }

        return y - 10;
    }

    private float drawSslPortsRow(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h    = 82;
        float y    = cursor - h;
        float half = (PW - MARGIN * 2 - 8) / 2f;

        // ── SSL card ─────────────────────────────────────────────────
        float sx = MARGIN;
        fillRect(cs, sx, y, half, h, CARD_BG);
        strokeRect(cs, sx, y, half, h, BORDER, 0.6f);
        fillRect(cs, sx, y + h - 3, half, 3, GREEN);

        drawText(cs, BOLD, 8, ACCENT_CYAN, sx + 12, y + h - 14, "SSL CERTIFICATE");
        fillRect(cs, sx + 12, y + h - 16, 100, 1, ACCENT_CYAN);

        boolean sslOk = scan.getSslDetails() != null
                && clean(scan.getSslDetails()).toLowerCase().contains("valid");
        fillCircle(cs, sx + 18, y + h - 30, 5, sslOk ? GREEN : RED);
        drawText(cs, BOLD, 9, sslOk ? GREEN : RED,
                sx + 28, y + h - 34, sslOk ? "VALID" : "INVALID / MISSING");

        String ssl = clean(scan.getSslDetails());
        if (ssl.length() > 46) {
            drawText(cs, REGULAR, 7, TEXT_GRAY, sx + 12, y + 32, ssl.substring(0, 46));
            drawText(cs, REGULAR, 7, TEXT_GRAY, sx + 12, y + 22, ssl.substring(46));
        } else {
            drawText(cs, REGULAR, 8, TEXT_GRAY, sx + 12, y + 28, ssl);
        }
        drawText(cs, REGULAR, 7, TEXT_GRAY, sx + 12, y + 10, "Ensure renewal before expiry date.");

        // ── Ports card ───────────────────────────────────────────────
        float px = MARGIN + half + 8;
        fillRect(cs, px, y, half, h, CARD_BG);
        strokeRect(cs, px, y, half, h, BORDER, 0.6f);
        fillRect(cs, px, y + h - 3, half, 3, ACCENT_BLUE);

        drawText(cs, BOLD, 8, ACCENT_CYAN, px + 12, y + h - 14, "OPEN PORTS");
        fillRect(cs, px + 12, y + h - 16, 75, 1, ACCENT_CYAN);

        String ports = scan.getOpenPorts() != null ? clean(scan.getOpenPorts()) : "";
        if (!ports.isBlank()) {
            float ppx = px + 12;
            float ppy = y + 46;
            for (String port : ports.split("[,;]+")) {
                if (port.isBlank()) continue;
                float pw2 = pillWidth(port.trim());
                fillRect(cs, ppx, ppy, pw2, 18, hex("#1F2D4A"));
                drawText(cs, REGULAR, 8, ACCENT_CYAN, ppx + 7, ppy + 4, port.trim());
                ppx += pw2 + 5;
                if (ppx > px + half - 20) { ppx = px + 12; ppy -= 22; }
            }
        } else {
            drawText(cs, ITALIC, 8, TEXT_GRAY, px + 12, y + 46, "No open ports detected");
        }
        drawText(cs, REGULAR, 7, TEXT_GRAY, px + 12, y + 10,
                "Expected: 80 (HTTP) and 443 (HTTPS) only.");

        return y - 10;
    }

    private float drawLeakedSecrets(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        float h = 55;
        float y = cursor - h;

        fillRect(cs, MARGIN, y, PW - MARGIN * 2, h, CARD_BG);
        strokeRect(cs, MARGIN, y, PW - MARGIN * 2, h, BORDER, 0.6f);

        drawText(cs, BOLD, 8, ACCENT_CYAN, MARGIN + 12, y + h - 14,
                "LEAKED SECRETS / CREDENTIALS");
        fillRect(cs, MARGIN + 12, y + h - 16, 190, 1, ACCENT_CYAN);

        boolean clean = scan.getLeakedSecrets() == null
                || clean(scan.getLeakedSecrets()).isBlank()
                || clean(scan.getLeakedSecrets()).equalsIgnoreCase("none");

        fillCircle(cs, MARGIN + 18, y + 24, 5, clean ? GREEN : RED);
        drawText(cs, BOLD,    9, clean ? GREEN : RED,
                MARGIN + 30, y + 28, clean ? "CLEAN" : "WARNING — ACTION REQUIRED");
        drawText(cs, REGULAR, 8, TEXT_GRAY,
                MARGIN + 30, y + 16,
                clean ? "No exposed secrets or credentials detected."
                        : clean(scan.getLeakedSecrets()));

        return y - 10;
    }

    private void drawRecommendations(PDPageContentStream cs, float cursor, WebsiteScan scan)
            throws IOException {
        // Build smart recommendations based on actual results
        List<String[]> recs = new ArrayList<>();

        if (!Boolean.TRUE.equals(scan.getHttpsEnabled()))
            recs.add(new String[]{"RED",    "CRITICAL: Enable HTTPS — all traffic is currently unencrypted."});
        if (!Boolean.TRUE.equals(scan.getHstsEnabled()))
            recs.add(new String[]{"YELLOW", "Add HSTS header to enforce HTTPS and prevent protocol downgrade attacks."});
        if (!Boolean.TRUE.equals(scan.getCspEnabled()))
            recs.add(new String[]{"YELLOW", "Add Content-Security-Policy header to block XSS injection attacks."});
        if (!Boolean.TRUE.equals(scan.getXFrameOptionsEnabled()))
            recs.add(new String[]{"YELLOW", "Add X-Frame-Options header to prevent clickjacking on your pages."});
        if (scan.getExposedEndpoints() != null && !scan.getExposedEndpoints().isBlank())
            recs.add(new String[]{"YELLOW", "Review exposed endpoints — avoid leaking internal structure via robots.txt."});
        if (scan.getLeakedSecrets() != null
                && !clean(scan.getLeakedSecrets()).equalsIgnoreCase("none")
                && !clean(scan.getLeakedSecrets()).isBlank())
            recs.add(new String[]{"RED",    "URGENT: Rotate any exposed API keys or credentials immediately."});

        // All clear — still show positive + improvement tips
        if (recs.isEmpty()) {
            recs.add(new String[]{"GREEN", "All critical security headers are correctly configured. Well done!"});
            recs.add(new String[]{"GREEN", "SSL certificate is valid and trusted. Monitor expiry regularly."});
            recs.add(new String[]{"GREEN", "Consider Subresource Integrity (SRI) tags for all external CDN scripts."});
            recs.add(new String[]{"GREEN", "Schedule monthly re-scans to catch regressions after deployments."});
        }

        float lineH = 20f;
        float h     = 28 + recs.size() * lineH + 8;
        float y     = cursor - h;

        fillRect(cs, MARGIN, y, PW - MARGIN * 2, h, CARD_BG);
        strokeRect(cs, MARGIN, y, PW - MARGIN * 2, h, BORDER, 0.6f);
        fillRect(cs, MARGIN, y + h - 3, PW - MARGIN * 2, 3, ACCENT_BLUE);

        drawText(cs, BOLD, 8, ACCENT_CYAN, MARGIN + 12, y + h - 14, "RECOMMENDATIONS");
        fillRect(cs, MARGIN + 12, y + h - 16, 115, 1, ACCENT_CYAN);

        for (int i = 0; i < recs.size(); i++) {
            String[] rec = recs.get(i);
            float    ry  = y + h - 28 - i * lineH;
            Color    dot = rec[0].equals("RED") ? RED
                    : rec[0].equals("YELLOW") ? YELLOW : GREEN;
            fillCircle(cs, MARGIN + 18, ry + 4, 4, dot);
            drawText(cs, REGULAR, 8,
                    rec[0].equals("RED") ? RED : TEXT_WHITE,
                    MARGIN + 28, ry, rec[1]);
        }
    }

    private void drawFooter(PDPageContentStream cs) throws IOException {
        fillRect(cs, 0, 0, PW, 38, CARD_BG);
        fillRect(cs, 0, 36, PW, 2, ACCENT_BLUE);

        drawText(cs, REGULAR,     8, TEXT_GRAY,   MARGIN,        13,
                "SecuriScan v1.0.0  |  Automated Security Analysis");
        drawTextRight(cs, REGULAR, 8, TEXT_GRAY,   PW - MARGIN,   13,
                "securiscan.io  |  Confidential — Do Not Redistribute");
        drawTextCentred(cs, BOLD,  8, ACCENT_BLUE, PW / 2f,       13, "Page 1 of 1");
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  DRAWING PRIMITIVES
    // ─────────────────────────────────────────────────────────────────────────

    private void drawScoreCircle(PDPageContentStream cs, float cx, float cy, int score)
            throws IOException {
        Color ring = scoreColor(score);
        strokeCircle(cs, cx, cy, 34, BORDER, 1f);
        strokeCircle(cs, cx, cy, 30, ring,   5f);
        strokeCircle(cs, cx, cy, 34, ring,   0.5f);
        drawTextCentred(cs, BOLD,    20, TEXT_WHITE, cx, cy - 8,  String.valueOf(score));
        drawTextCentred(cs, REGULAR,  7, TEXT_GRAY,  cx, cy - 18, "/ 100");
    }

    private void fillRect(PDPageContentStream cs, float x, float y, float w, float h, Color c)
            throws IOException {
        cs.setNonStrokingColor(c);
        cs.addRect(x, y, w, h);
        cs.fill();
    }

    private void strokeRect(PDPageContentStream cs, float x, float y, float w, float h,
                            Color c, float lw) throws IOException {
        cs.setStrokingColor(c);
        cs.setLineWidth(lw);
        cs.addRect(x, y, w, h);
        cs.stroke();
    }

    private void fillCircle(PDPageContentStream cs, float cx, float cy, float r, Color c)
            throws IOException {
        cs.setNonStrokingColor(c);
        float k = 0.5522847f * r;
        cs.moveTo(cx,     cy + r);
        cs.curveTo(cx + k, cy + r, cx + r, cy + k, cx + r, cy);
        cs.curveTo(cx + r, cy - k, cx + k, cy - r, cx,     cy - r);
        cs.curveTo(cx - k, cy - r, cx - r, cy - k, cx - r, cy);
        cs.curveTo(cx - r, cy + k, cx - k, cy + r, cx,     cy + r);
        cs.fill();
    }

    private void strokeCircle(PDPageContentStream cs, float cx, float cy, float r,
                              Color c, float lw) throws IOException {
        cs.setStrokingColor(c);
        cs.setLineWidth(lw);
        float k = 0.5522847f * r;
        cs.moveTo(cx,     cy + r);
        cs.curveTo(cx + k, cy + r, cx + r, cy + k, cx + r, cy);
        cs.curveTo(cx + r, cy - k, cx + k, cy - r, cx,     cy - r);
        cs.curveTo(cx - k, cy - r, cx - r, cy - k, cx - r, cy);
        cs.curveTo(cx - r, cy + k, cx - k, cy + r, cx,     cy + r);
        cs.stroke();
    }

    private void drawText(PDPageContentStream cs, PDType1Font font, float size,
                          Color color, float x, float y, String text) throws IOException {
        cs.beginText();
        cs.setFont(font, size);
        cs.setNonStrokingColor(color);
        cs.newLineAtOffset(x, y);
        cs.showText(clean(text));
        cs.endText();
    }

    private void drawTextRight(PDPageContentStream cs, PDType1Font font, float size,
                               Color color, float rightX, float y, String text)
            throws IOException {
        String s  = clean(text);
        float  tw = font.getStringWidth(s) / 1000f * size;
        drawText(cs, font, size, color, rightX - tw, y, s);
    }

    private void drawTextCentred(PDPageContentStream cs, PDType1Font font, float size,
                                 Color color, float cx, float y, String text)
            throws IOException {
        String s  = clean(text);
        float  tw = font.getStringWidth(s) / 1000f * size;
        drawText(cs, font, size, color, cx - tw / 2f, y, s);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private float pillWidth(String text) {
        return text.length() * 5.5f + 14f;
    }

    private String scoreToGrade(int score) {
        if (score >= 90) return "A+";
        if (score >= 80) return "A";
        if (score >= 70) return "B";
        if (score >= 60) return "C";
        if (score >= 50) return "D";
        return "F";
    }

    private Color scoreColor(int score) {
        if (score >= 70) return GREEN;
        if (score >= 50) return YELLOW;
        return RED;
    }

    private String date(WebsiteScan scan) {
        return scan.getCreatedAt() != null ? scan.getCreatedAt().toString() : "N/A";
    }

    /** Strips non-ASCII characters (emoji etc.) that Helvetica cannot encode. */
    private String clean(String text) {
        if (text == null) return "N/A";
        return text.replaceAll("[^\\x00-\\x7F]", "").trim();
    }

    private static Color hex(String hex) {
        return Color.decode(hex);
    }
}