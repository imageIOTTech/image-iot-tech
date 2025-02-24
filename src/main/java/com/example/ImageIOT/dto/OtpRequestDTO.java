package com.example.ImageIOT.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OtpRequestDTO {
    
    @NotBlank
    private String email;

    @NotBlank
    private String otp;
}