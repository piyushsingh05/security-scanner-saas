package com.securityscanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class SecurityScannerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityScannerApplication.class, args);
	}

}
