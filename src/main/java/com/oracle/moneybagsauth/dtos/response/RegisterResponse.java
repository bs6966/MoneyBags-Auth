package com.oracle.moneybagsauth.dtos.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class RegisterResponse {
    private Long id;
    private String username;
}
