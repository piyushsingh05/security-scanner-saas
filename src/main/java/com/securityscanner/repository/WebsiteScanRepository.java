package com.securityscanner.repository;

import com.securityscanner.entity.WebsiteScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface WebsiteScanRepository extends JpaRepository<WebsiteScan, Long> {

    List<WebsiteScan> findTop5ByOrderByCreatedAtDesc();

    @Query("SELECT COUNT(w) FROM WebsiteScan w")
    Long getTotalScans();

    @Query("SELECT AVG(w.score) FROM WebsiteScan w")
    Double getAverageScore();

    @Query("SELECT COUNT(w) FROM WebsiteScan w WHERE w.score < 60")
    Long getCriticalSites();
}
