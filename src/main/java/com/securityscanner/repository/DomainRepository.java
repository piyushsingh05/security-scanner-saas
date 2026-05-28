package com.securityscanner.repository;

import com.securityscanner.entity.Domain;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface DomainRepository extends JpaRepository<Domain,Long> {
    List<Domain> findByUserEmailOrderByAddedAtDesc(String email);
    boolean existsByUserEmailAndDomain(String email, String domain);
    Optional<Domain> findByUserEmailAndDomain(String email, String domain);
}
