package com.example.ImageIOT.service;

import com.example.ImageIOT.exception.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class OtpService {

    private final Map<String, String> otpStorage = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final EmailService emailService;

    private static final int OTP_Bound = 1000000;

    public OtpService(EmailService emailService) {
        this.emailService = emailService;
    }

    public String generateOtp(String email) {
        String otp = String.format("%06d", random.nextInt(OTP_Bound));
        otpStorage.put(email, otp);
        emailService.sendOtpEmail(email, otp);
        return otp;
    }

    public boolean validateOtp(String email, String otp) {
        String storedOtp = otpStorage.get(email);
        return otp != null && otp.equals(storedOtp);
    }

    public void validateOtpOrThrow(String email, String otp) {
        if (!validateOtp(email, otp)) {
            log.warn("Invalid OTP for {}: {}", email, otp);
            throw new CustomException("Invalid OTP for email: " + email, 401);
        }
        log.debug("Valid OTP for {}: {}", email, otp);
    }

    public void clearOtp(String email) {
        otpStorage.remove(email);
    }
}
