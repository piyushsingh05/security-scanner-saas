package com.securityscanner.controller;

import com.securityscanner.config.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (adminUsername.equals(username) && adminPassword.equals(password)) {
            String token = jwtUtil.generateToken(username);
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", username
            ));
        }
        return ResponseEntity.status(401)
                .body(Map.of("error", "Invalid credentials"));
    }

    @GetMapping("/check")
    public ResponseEntity<?> check() {
        // If request reaches here, JWT filter already validated the token
        return ResponseEntity.ok(Map.of("loggedIn", true));
    }
}