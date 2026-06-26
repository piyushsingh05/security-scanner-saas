package com.securityscanner.repository;

import com.securityscanner.entity.WebsiteScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface WebsiteScanRepository extends JpaRepository<WebsiteScan, Long> {


    List<WebsiteScan> findTop5ByOrderByCreatedAtDesc();

    List<WebsiteScan> findByUserEmailOrderByCreatedAtDesc(String email);

    // ── Per-user stats (used by ScanController) ──
    long countByUserEmail(String email);

    @Query("SELECT COALESCE(AVG(w.score), 0) FROM WebsiteScan w WHERE w.user.email = :email")
    Double getAverageScoreByUserEmail(@Param("email") String email);

    @Query("SELECT COUNT(w) FROM WebsiteScan w WHERE w.user.email = :email AND w.score < 50")
    long getCriticalSitesByUserEmail(@Param("email") String email);

    Optional<WebsiteScan> findTopByDomainAndUserEmailOrderByCreatedAtDesc(
            String domain, String email);

    List<WebsiteScan> findTop2ByDomainAndUserEmailOrderByCreatedAtDesc(String domain, String userEmail);
}
