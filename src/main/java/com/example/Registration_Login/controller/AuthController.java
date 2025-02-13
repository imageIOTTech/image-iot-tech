package com.example.Registration_Login.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.Registration_Login.dto.LoginRequestDTO;
import com.example.Registration_Login.dto.LoginResponse;
import com.example.Registration_Login.dto.OtpRequestDTO;
import com.example.Registration_Login.dto.UserRequestDTO;
import com.example.Registration_Login.dto.UserResponseDTO;
import com.example.Registration_Login.model.RefreshToken;
import com.example.Registration_Login.model.User;
import com.example.Registration_Login.service.OtpService;
import com.example.Registration_Login.service.RefreshTokenService;
import com.example.Registration_Login.service.UserService;
import com.example.Registration_Login.util.JwtUtil;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
// @RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final OtpService otpService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@RequestBody @Validated UserRequestDTO userRequestDTO) {
        User user = userService.registerUserLocal(userRequestDTO);

        UserResponseDTO responseDTO = new UserResponseDTO();
        responseDTO.setName(user.getName());
        responseDTO.setEmail(user.getEmail());
        responseDTO.setPhonenumber(user.getPhonenumber());
        responseDTO.setAuthProvider(user.getAuthProvider());

        return ResponseEntity.ok(responseDTO);
    }

    @PostMapping("/login/local")
    public ResponseEntity<String> loginLocal(@RequestBody LoginRequestDTO loginRequestDTO) {
        User user = userService.loginUserLocal(loginRequestDTO);
        String otp = otpService.generateOtp(user.getEmail());
        logger.debug("OTP cho {}: {}", user.getEmail(), otp);
        return ResponseEntity.ok("OTP đã được gửi tới email của bạn.");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<LoginResponse> verifyOtp(@RequestBody OtpRequestDTO otpRequestDTO) {
        otpService.validateOtpOrThrow(otpRequestDTO.getEmail(), otpRequestDTO.getOtp());

        User user = userService.findByEmail(otpRequestDTO.getEmail());
        String accessToken = jwtUtil.generateToken(user.getEmail(), user.getRoles());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        otpService.clearOtp(user.getEmail());

        LoginResponse response = new LoginResponse(
                accessToken, "Bearer", refreshToken.getToken(),
                user.getId(), user.getName(), user.getEmail(), user.getRoles());

        logger.debug("Xác thực OTP thành công cho {}: {}", otpRequestDTO.getEmail(), otpRequestDTO.getOtp());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/login/{provider}")
    public ResponseEntity<String> loginAuth(@PathVariable String provider, HttpServletResponse response)
            throws IOException {
        response.sendRedirect("/oauth2/authorization/" + provider);
        return ResponseEntity.ok("Đang chuyển hướng...");
    }

    @GetMapping("/loginSuccess/{provider}")
    public ResponseEntity<LoginResponse> handleLoginSuccess(
            @PathVariable String provider, OAuth2AuthenticationToken oAuth2AuthenticationToken) {

        User user;

        switch (provider.toLowerCase()) {
            case "google":
                user = userService.loginRegisterByGoogleOauth2(oAuth2AuthenticationToken);
                break;
            case "facebook":
                user = userService.loginRegisterByFacebookOauth2(oAuth2AuthenticationToken);
                break;
            case "github":
                user = userService.loginRegisterByGithubOauth2(oAuth2AuthenticationToken);
                break;
            default:
                throw new RuntimeException("Unsupported provider: " + provider);
        }

        String accessToken = jwtUtil.generateToken(user.getEmail(), user.getRoles());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        LoginResponse response = new LoginResponse(
                accessToken, "Bearer", refreshToken.getToken(),
                user.getId(), user.getName(), user.getEmail(), user.getRoles());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> request) {
        String requestRefreshToken = request.get("refreshToken");

        Map<String, String> tokens = refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(refreshToken -> {
                    User user = refreshToken.getUser();
                    String newAccessToken = jwtUtil.generateToken(user.getEmail(), user.getRoles());
                    Map<String, String> map = new HashMap<>();
                    map.put("accessToken", newAccessToken);
                    map.put("refreshToken", requestRefreshToken);
                    return map;
                })
                .orElseThrow(() -> new RuntimeException("Refresh token không hợp lệ"));
        return ResponseEntity.ok(tokens);
    }
}
