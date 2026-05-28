package com.securityscanner.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
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

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(length = 2000)
    private String exposedEndpoints;

    @Column(length = 1000)
    private String sslDetails;

    @Column(length = 1000)
    private String corsFindings;

    @Column(length = 1000)
    private String cookieSecurityFindings;

    @Column(length = 1000)
    private String openPorts;

    @Column(length = 3000)
    private String leakedSecrets;

    @Column(columnDefinition = "TEXT")
    private String directoryFindings;

}
