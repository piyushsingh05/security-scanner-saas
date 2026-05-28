package com.securityscanner.controller;

import com.securityscanner.config.JwtUtil;
import com.securityscanner.dto.RegisterRequest;
import com.securityscanner.entity.User;
import com.securityscanner.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

//    @Value("${admin.username}")
//    private String adminUsername;
//
//    @Value("${admin.password}")
//    private String adminPassword;

//    @PostMapping("/login")
//    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
//        String username = body.get("username");
//        String password = body.get("password");
//
//        if (adminUsername.equals(username) && adminPassword.equals(password)) {
//            String token = jwtUtil.generateToken(username);
//            return ResponseEntity.ok(Map.of(
//                    "token", token,
//                    "username", username
//            ));
//        }
//        return ResponseEntity.status(401)
//                .body(Map.of("error", "Invalid credentials"));
//    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {

        String email = body.get("email");
        String password = body.get("password");

        User user = userRepository.findByEmail(email)
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "User not found"));
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid password"));
        }

        String token = jwtUtil.generateToken(user.getEmail());

        return ResponseEntity.ok(Map.of(
                "token", token,
                "email", user.getEmail()
        ));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        if(userRepository.findByEmail(request.getEmail()).isPresent()){
            return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        userRepository.save(user);

        String token = jwtUtil.generateToken(user.getEmail());

        return ResponseEntity.ok(Map.of("token", token,
                "email", user.getEmail()));
    }

    @GetMapping("/check")
    public ResponseEntity<?> check() {
        // If request reaches here, JWT filter already validated the token
        return ResponseEntity.ok(Map.of("loggedIn", true));
    }
}