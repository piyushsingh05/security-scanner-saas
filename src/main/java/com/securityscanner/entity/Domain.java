package com.securityscanner.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "domains")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Domain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false)
    private String domain;

    @Builder.Default
    private Boolean verified = false;

    private Integer lastScore;
    private LocalDateTime lastScannedAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime addedAt;

    @PrePersist
    public void prePersist() {
        this.addedAt = LocalDateTime.now();
    }

    // --- NEW FIELDS ---
    @Builder.Default
    @Enumerated(EnumType.STRING)
    private ScanFrequency scanFrequency = ScanFrequency.WEEKLY;

    @Builder.Default
    private Boolean emailAlertsEnabled = true;

    public enum ScanFrequency {
        DAILY, WEEKLY, MONTHLY
    }
}
