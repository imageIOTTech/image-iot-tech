package com.example.ImageIOT.dto;

import java.util.Set;

import com.example.ImageIOT.enums.Role;

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