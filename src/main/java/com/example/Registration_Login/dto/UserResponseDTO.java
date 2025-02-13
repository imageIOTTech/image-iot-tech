package com.example.Registration_Login.dto;

import com.example.Registration_Login.enums.AuthProvider;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {

    
    private String name;
    private String email;
    private Long phonenumber;
    private AuthProvider authProvider;
}