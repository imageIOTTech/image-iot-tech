package com.example.Registration_Login.service;

import com.example.Registration_Login.exception.CustomException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

@Service
public class OtpService {

    private final Map<String, String> otpStorage = new HashMap<>();
    private final SecureRandom random = new SecureRandom();
    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);

    public String generateOtp(String email) {
        String otp = String.format("%06d", random.nextInt(1000000));
        otpStorage.put(email, otp);
        logger.info("Generated OTP for {}: {}", email, otp);
        return otp;
    }

    public boolean validateOtp(String email, String otp) {
        String storedOtp = otpStorage.get(email);
        return otp != null && otp.equals(storedOtp);
    }

    public void validateOtpOrThrow(String email, String otp) {
        if (!validateOtp(email, otp)) {
            logger.warn("OTP không hợp lệ cho {}: {}", email, otp);
            throw new CustomException("OTP không hợp lệ cho email: " + email, 401);
        }
        logger.debug("OTP hợp lệ cho {}: {}", email, otp);
    }

    public void clearOtp(String email) {
        otpStorage.remove(email);
    }
}
