package com.example.ImageIOT.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.ImageIOT.dto.LoginRequestDTO;
import com.example.ImageIOT.dto.LoginResponse;
import com.example.ImageIOT.dto.OtpRequestDTO;
import com.example.ImageIOT.dto.UserRequestDTO;
import com.example.ImageIOT.dto.UserResponseDTO;
import com.example.ImageIOT.service.UserService;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import lombok.RequiredArgsConstructor;
import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@RequestBody UserRequestDTO userRequestDTO) {
        UserResponseDTO response = userService.registerUserLocal(userRequestDTO);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login/local")
    public ResponseEntity<Boolean> loginLocal(@RequestBody @Validated LoginRequestDTO loginRequestDTO) {
        boolean result = userService.loginLocal(loginRequestDTO);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<LoginResponse> verifyOtp(@RequestBody @Validated OtpRequestDTO otpRequestDTO) {
        LoginResponse response = userService.verifyOtp(otpRequestDTO);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/login/{provider}")
    public void loginAuth(@PathVariable String provider, HttpServletResponse response)
            throws IOException {
        response.sendRedirect("/oauth2/authorization/" + provider);
    }

    @GetMapping("/loginSuccess/{provider}")
    public ResponseEntity<LoginResponse> loginSuccess(@PathVariable String provider,
            OAuth2AuthenticationToken oAuth2AuthenticationToken) {
        LoginResponse response = userService.handleLoginSuccess(provider, oAuth2AuthenticationToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        LoginResponse response = userService.refreshToken(refreshToken);
        return ResponseEntity.ok(response);
    }
}
