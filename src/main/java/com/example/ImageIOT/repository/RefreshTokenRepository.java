package com.example.ImageIOT.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.ImageIOT.model.RefreshToken;
import com.example.ImageIOT.model.User;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);
}