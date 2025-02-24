package com.example.ImageIOT.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.ImageIOT.dto.LoginRequestDTO;
import com.example.ImageIOT.dto.LoginResponse;
import com.example.ImageIOT.dto.OtpRequestDTO;
import com.example.ImageIOT.dto.UserRequestDTO;
import com.example.ImageIOT.dto.UserResponseDTO;
import com.example.ImageIOT.enums.AuthProvider;
import com.example.ImageIOT.enums.Role;
import com.example.ImageIOT.exception.CustomException;
import com.example.ImageIOT.model.RefreshToken;
import com.example.ImageIOT.model.User;
import com.example.ImageIOT.repository.UserRepository;
import com.example.ImageIOT.util.JwtUtil;

import java.util.Collections;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public UserResponseDTO registerUserLocal(UserRequestDTO userRequestDTO) {
        User user = new User();
        user.setName(userRequestDTO.getName());
        user.setEmail(userRequestDTO.getEmail());
        user.setPhonenumber(userRequestDTO.getPhonenumber());
        user.setPassword(userRequestDTO.getPassword());
        user.setAuthProvider(AuthProvider.LOCAL);
        user.setRoles(Collections.singleton(Role.USER));

        List<User> existingUsers = userRepository.findByEmail(user.getEmail());
        for (User existingUser : existingUsers) {
            if (existingUser.getAuthProvider() == AuthProvider.GOOGLE ||
                    existingUser.getAuthProvider() == AuthProvider.LOCAL) {
                throw new CustomException("Email already exists with Google or Local. Registration is not allowed.",
                        409);
            }
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user = userRepository.save(user);

        UserResponseDTO response = new UserResponseDTO();
        response.setName(user.getName());
        response.setEmail(user.getEmail());
        response.setPhonenumber(user.getPhonenumber());
        response.setAuthProvider(user.getAuthProvider());
        return response;
    }

    public boolean loginLocal(LoginRequestDTO loginRequestDTO) {
        User user = loginUserLocalInternal(loginRequestDTO);
        String otp = otpService.generateOtp(user.getEmail());
        log.debug("OTP for {}: {}", user.getEmail(), otp);
        return true;
    }

    private User loginUserLocalInternal(LoginRequestDTO loginRequestDTO) {
        List<User> users = userRepository.findByEmail(loginRequestDTO.getEmail());
        if (users.isEmpty()) {
            throw new CustomException("User not found with email: " + loginRequestDTO.getEmail(), 404);
        }
        User user = users.get(0);
        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), user.getPassword())) {
            throw new CustomException("Invalid password", 401);
        }
        return user;
    }

    public LoginResponse verifyOtp(OtpRequestDTO otpRequestDTO) {
        otpService.validateOtpOrThrow(otpRequestDTO.getEmail(), otpRequestDTO.getOtp());
        User user = findByEmail(otpRequestDTO.getEmail());
        String accessToken = jwtUtil.generateToken(user.getEmail(), user.getId(), user.getRoles());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        otpService.clearOtp(user.getEmail());
        log.debug("OTP verification successful for {}: {}", otpRequestDTO.getEmail(), otpRequestDTO.getOtp());
        return new LoginResponse(accessToken, "Bearer", refreshToken.getToken(),
                user.getId(), user.getName(), user.getEmail(), user.getRoles());
    }

    public LoginResponse handleLoginSuccess(String provider, OAuth2AuthenticationToken auth2AuthenticationToken) {
        User user;
        switch (provider.toLowerCase()) {
            case "google":
                user = loginRegisterByGoogleOauth2(auth2AuthenticationToken);
                break;
            case "facebook":
                user = loginRegisterByFacebookOauth2(auth2AuthenticationToken);
                break;
            case "github":
                user = loginRegisterByGithubOauth2(auth2AuthenticationToken);
                break;
            default:
                throw new CustomException("Unsupported provider: " + provider, 400);
        }
        String accessToken = jwtUtil.generateToken(user.getEmail(), user.getId(), user.getRoles());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        return new LoginResponse(accessToken, "Bearer", refreshToken.getToken(),
                user.getId(), user.getName(), user.getEmail(), user.getRoles());
    }

    public LoginResponse refreshToken(String refreshTokenStr) {
        return refreshTokenService.findByToken(refreshTokenStr)
                .map(refreshTokenService::verifyExpiration)
                .map(refreshToken -> {
                    User user = refreshToken.getUser();
                    String newAccessToken = jwtUtil.generateToken(user.getEmail(), user.getId(), user.getRoles());
                    return new LoginResponse(newAccessToken, "Bearer", refreshTokenStr,
                            user.getId(), user.getName(), user.getEmail(), user.getRoles());
                })
                .orElseThrow(() -> new CustomException("Invalid refresh token", 400));
    }

    public User findByEmail(String email) {
        List<User> users = userRepository.findByEmail(email);
        if (users.isEmpty()) {
            throw new CustomException("User not found with email: " + email, 404);
        }
        return users.get(0);
    }

    public User loginRegisterByGoogleOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {
        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        log.info("USER EMAIL FROM GOOGLE IS {}", email);
        log.info("USER NAME FROM GOOGLE IS {}", name);
        List<User> users = userRepository.findByEmail(email);
        if (!users.isEmpty()) {
            for (User user : users) {
                if (user.getAuthProvider() == AuthProvider.GOOGLE) {
                    return user;
                } else if (user.getAuthProvider() == AuthProvider.LOCAL) {
                    user.setAuthProvider(AuthProvider.GOOGLE);
                    userRepository.save(user);
                    return user;
                }
            }
        }
        User newUser = new User();
        newUser.setEmail(email);
        newUser.setName(name);
        newUser.setAuthProvider(AuthProvider.GOOGLE);
        newUser.setRoles(Collections.singleton(Role.USER));
        return userRepository.save(newUser);
    }

    public User loginRegisterByFacebookOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {
        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        log.info("USER EMAIL FROM FACEBOOK IS {}", email);
        log.info("USER NAME FROM FACEBOOK IS {}", name);
        User user = userRepository.findByEmailAndAuthProvider(email, AuthProvider.FACEBOOK).orElse(null);
        if (user != null) {
            return user;
        }
        user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setAuthProvider(AuthProvider.FACEBOOK);
        user.setRoles(Collections.singleton(Role.USER));
        return userRepository.save(user);
    }

    public User loginRegisterByGithubOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {
        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("login");
        log.info("USER EMAIL FROM GITHUB IS {}", email);
        log.info("USER LOGIN NAME FROM GITHUB IS {}", name);
        User user = userRepository.findByEmailAndAuthProvider(email, AuthProvider.GITHUB).orElse(null);
        if (user == null) {
            user = new User();
            user.setName(name);
            user.setEmail(email);
            user.setAuthProvider(AuthProvider.GITHUB);
            user.setRoles(Collections.singleton(Role.USER));
            return userRepository.save(user);
        }
        return user;
    }
}
