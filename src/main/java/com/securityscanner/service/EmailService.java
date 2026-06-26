package com.securityscanner.service;

import com.securityscanner.entity.WebsiteScan;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class EmailService {

    /**
     * Stub — logs to console now.
     * Later: inject JavaMailSender + fill in sendMimeMessage()
     */
    public void sendAlertEmail(String toEmail, String domain,
                               int oldScore, int newScore,
                               String changes) {
        log.warn("""
                [EMAIL ALERT - STUB]
                To      : {}
                Domain  : {}
                Score   : {} → {}
                Changes : {}
                """, toEmail, domain, oldScore, newScore, changes);

        // TODO when Gmail ready:
        // MimeMessage msg = mailSender.createMimeMessage();
        // MimeMessageHelper h = new MimeMessageHelper(msg, true);
        // h.setTo(toEmail);
        // h.setSubject("⚠ SecuriScan Alert: " + domain);
        // h.setText(buildHtmlBody(...), true);
        // mailSender.send(msg);
    }

    public void sendSslExpiryAlert(String toEmail, String domain, String sslDetails) {
        log.warn("""
                [SSL EXPIRY ALERT - STUB]
                To      : {}
                Domain  : {}
                SSL     : {}
                """, toEmail, domain, sslDetails);
    }
}