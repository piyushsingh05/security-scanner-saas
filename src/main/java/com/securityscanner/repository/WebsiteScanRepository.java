package com.securityscanner.repository;

import com.securityscanner.entity.WebsiteScan;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WebsiteScanRepository extends JpaRepository<WebsiteScan, Long> {
}
