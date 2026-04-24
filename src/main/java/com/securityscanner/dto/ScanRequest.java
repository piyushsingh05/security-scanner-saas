package com.securityscanner.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;


public class ScanRequest {

    private String domain;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
