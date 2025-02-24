package com.example.ImageIOT.dto;

import lombok.Data;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Data
public class LoginRequestDTO {
    
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;
}
