package com.example.Registration_Login.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import com.example.Registration_Login.dto.LoginRequestDTO;
import com.example.Registration_Login.dto.LoginResponse;
import com.example.Registration_Login.dto.OtpRequestDTO;
import com.example.Registration_Login.dto.UserRequestDTO;
import com.example.Registration_Login.dto.UserResponseDTO;
import com.example.Registration_Login.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@RequestBody @Validated UserRequestDTO userRequestDTO) {
        UserResponseDTO response = userService.registerUserLocal(userRequestDTO);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login/local")
    public ResponseEntity<String> loginLocal(@RequestBody LoginRequestDTO loginRequestDTO) {
        String message = userService.loginLocal(loginRequestDTO);
        return ResponseEntity.ok(message);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<LoginResponse> verifyOtp(@RequestBody OtpRequestDTO otpRequestDTO) {
        LoginResponse response = userService.verifyOtp(otpRequestDTO);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/login/{provider}")
    public ResponseEntity<String> loginAuth(@PathVariable String provider, HttpServletResponse response)
            throws IOException {
        response.sendRedirect("/oauth2/authorization/" + provider);
        return ResponseEntity.ok("Redirecting...");
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
