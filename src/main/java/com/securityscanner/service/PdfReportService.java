package com.securityscanner.service;

import com.securityscanner.entity.WebsiteScan;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.io.IOException;

@Service
public class PdfReportService {
    public String generateReport(WebsiteScan scan) {
        String fileName = "report_" + scan.getId() + ".pdf";

        try (PDDocument document = new PDDocument()) {

            PDPage page = new PDPage();
            document.addPage(page);

            PDPageContentStream content =
                    new PDPageContentStream(document, page);

            content.beginText();
            content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
            content.setLeading(16f);
            content.newLineAtOffset(50, 750);

            content.showText("Website Security Audit Report");
            content.newLine();

            content.showText("Domain: " + scan.getDomain());
            content.newLine();

            content.showText("Score: " + scan.getScore());
            content.newLine();

            content.showText("Status: " + scan.getStatus());
            content.newLine();

            content.showText("HTTPS Enabled: " + scan.getHttpsEnabled());
            content.newLine();

            content.showText("X-Frame-Options: " + scan.getXFrameOptionsEnabled());
            content.newLine();

            content.showText("CSP Enabled: " + scan.getCspEnabled());
            content.newLine();

            content.showText("HSTS Enabled: " + scan.getHstsEnabled());
            content.newLine();

            content.endText();
            content.close();

            document.save(fileName);
            System.out.println("PDF saved at: " + new java.io.File(fileName).getAbsolutePath());
            return fileName;

        } catch (IOException e) {
            throw new RuntimeException("PDF generation failed");
        }
    }
}
