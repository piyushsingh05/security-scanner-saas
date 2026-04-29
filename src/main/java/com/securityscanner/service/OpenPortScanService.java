package com.securityscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class OpenPortScanService {

    private static final int CONNECTION_TIMEOUT = 1000;

    private static final int[] COMMON_PORTS = {
            21,     // FTP
            22,     // SSH
            25,     // SMTP
            53,     // DNS
            80,     // HTTP
            110,    // POP3
            143,    // IMAP
            443,    // HTTPS
            3306,   // MySQL
            5432,   // PostgreSQL
            6379,   // Redis
            8080,   // Tomcat
            27017   // MongoDB
    };

    public List<String> scanOpenPorts(String domain) {
        log.info("[OpenPortScanService] Starting port scan for domain: {}", domain);

        long start = System.currentTimeMillis();
        List<String> openPorts = new ArrayList<>();

        for (int port : COMMON_PORTS) {
            if (isPortOpen(domain, port)) {
                String portInfo = formatPortName(port);
                openPorts.add(portInfo);

                log.info("[OpenPortScanService] Open port found: {}", portInfo);
            }
        }

        long elapsed = System.currentTimeMillis() - start;

        log.info(
                "[OpenPortScanService] Scan completed in {} ms | domain={} | openPorts={}",
                elapsed,
                domain,
                openPorts
        );

        return openPorts;
    }

    private boolean isPortOpen(String domain, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(
                    new InetSocketAddress(domain, port),
                    CONNECTION_TIMEOUT
            );
            return true;

        } catch (Exception ignored) {
            return false;
        }
    }

    private String formatPortName(int port) {
        return switch (port) {
            case 21 -> "21 (FTP)";
            case 22 -> "22 (SSH)";
            case 25 -> "25 (SMTP)";
            case 53 -> "53 (DNS)";
            case 80 -> "80 (HTTP)";
            case 110 -> "110 (POP3)";
            case 143 -> "143 (IMAP)";
            case 443 -> "443 (HTTPS)";
            case 3306 -> "3306 (MySQL)";
            case 5432 -> "5432 (PostgreSQL)";
            case 6379 -> "6379 (Redis)";
            case 8080 -> "8080 (Tomcat)";
            case 27017 -> "27017 (MongoDB)";
            default -> port + " (Unknown Service)";
        };
    }
}