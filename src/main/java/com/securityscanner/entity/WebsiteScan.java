package com.securityscanner.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "website_scan")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebsiteScan {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String domain;
    private String status;
    private Integer score;
    private Boolean httpsEnabled;
    private LocalDateTime createdAt;
    private Boolean xFrameOptionsEnabled;
    private Boolean cspEnabled;
    private Boolean hstsEnabled;
    private String exposedEndpoints;

    @Column(length = 1000)
    private String sslDetails;

    @Column(length = 1000)
    private String openPorts;
}
