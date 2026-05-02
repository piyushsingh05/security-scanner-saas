package com.securityscanner.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Service
public class OpenPortScanService {

    private static final int CONNECTION_TIMEOUT = 1000;

    private static final int[] COMMON_PORTS = {
            21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 27017
    };

    public record PortResult(int port, String service) {
        @Override
        public String toString() {
            return port + " (" + service + ")";
        }
    }

    public List<PortResult> scanOpenPorts(String domain) {
        log.info("[OpenPortScanService] Starting port scan for domain: {}", domain);

        // ✅ Resolve domain → IP once, upfront
        String ip;
        try {
            ip = InetAddress.getByName(domain).getHostAddress();
            log.info("[OpenPortScanService] Resolved {} → {}", domain, ip);
        } catch (UnknownHostException e) {
            log.error("[OpenPortScanService] Failed to resolve domain: {}", domain);
            throw new IllegalArgumentException("Cannot resolve domain: " + domain, e);
        }

        long start = System.currentTimeMillis();

        // ✅ CopyOnWriteArrayList — thread-safe, no manual synchronized block needed
        List<PortResult> openPorts = new CopyOnWriteArrayList<>();

        Arrays.stream(COMMON_PORTS)
                .parallel()
                .forEach(port -> {
                    if (isPortOpen(ip, port)) {
                        PortResult result = new PortResult(port, resolveServiceName(port));
                        openPorts.add(result);
                        log.info("[OpenPortScanService] Open port found: {}", result);
                    }
                });

        long elapsed = System.currentTimeMillis() - start;
        log.info("[OpenPortScanService] Scan completed in {}ms | domain={} | ip={} | openPorts={}",
                elapsed, domain, ip, openPorts);

        return openPorts;
    }

    private boolean isPortOpen(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), CONNECTION_TIMEOUT);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private String resolveServiceName(int port) {
        return switch (port) {
            case 21    -> "FTP";
            case 22    -> "SSH";
            case 25    -> "SMTP";
            case 53    -> "DNS";
            case 80    -> "HTTP";
            case 110   -> "POP3";
            case 143   -> "IMAP";
            case 443   -> "HTTPS";
            case 3306  -> "MySQL";
            case 5432  -> "PostgreSQL";
            case 6379  -> "Redis";
            case 8080  -> "Tomcat";
            case 27017 -> "MongoDB";
            default    -> "Unknown";
        };
    }
}