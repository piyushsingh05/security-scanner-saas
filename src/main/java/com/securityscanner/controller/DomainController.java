package com.securityscanner.controller;

import com.securityscanner.entity.Domain;
import com.securityscanner.entity.User;
import com.securityscanner.repository.DomainRepository;
import com.securityscanner.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/domains")
@RequiredArgsConstructor
public class DomainController {

    private final DomainRepository domainRepository;
    private final UserRepository userRepository;

    @GetMapping
    public ResponseEntity<List<Domain>> getDomains() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ResponseEntity.ok(domainRepository.findByUserEmailOrderByAddedAtDesc(email));
    }

    @PostMapping
    public ResponseEntity<?> addDomain(@RequestBody Map<String, String> body) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        String domain = body.get("domain").trim().toLowerCase()
                .replaceAll("https?://", "").replaceAll("/.*", "");

        if (domainRepository.existsByUserEmailAndDomain(email, domain))
            return ResponseEntity.badRequest().body(Map.of("error", "Domain already added"));

        User user = userRepository.findByEmail(email).orElseThrow();
        Domain d = Domain.builder().user(user).domain(domain).build();
        return ResponseEntity.ok(domainRepository.save(d));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteDomain(@PathVariable Long id) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        Domain d = domainRepository.findById(id).orElseThrow();
        if (!d.getUser().getEmail().equals(email))
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden"));
        domainRepository.delete(d);
        return ResponseEntity.ok(Map.of("deleted", true));
    }
}
