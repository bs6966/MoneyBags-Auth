package com.oracle.moneybagsauth.dtos.requests;

import com.oracle.moneybagsauth.models.Authority;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Set;

@Data
public class RegisterRequest {
    @NotBlank
    private String username;
    @NotBlank private String password;

    private Set<Authority> roles;
}

