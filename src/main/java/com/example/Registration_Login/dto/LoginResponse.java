package com.example.Registration_Login.dto;

import java.util.Set;

import com.example.Registration_Login.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponse {

    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private Long userId;
    private String name;
    private String email;
    private Set<Role> roles;
}