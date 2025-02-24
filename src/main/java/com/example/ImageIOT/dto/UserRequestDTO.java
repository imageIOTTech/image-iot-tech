package com.example.ImageIOT.dto;

import com.example.ImageIOT.enums.AuthProvider;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestDTO {

    private String name;
    private String email;
    private Long phonenumber;
    private String password;
}
