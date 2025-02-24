package com.example.ImageIOT.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.ImageIOT.enums.AuthProvider;
import com.example.ImageIOT.model.User;

import java.util.List;



public interface UserRepository extends JpaRepository<User, Long>{

    Optional<User> findByEmailAndPhonenumber(String email, Long phonenumber);

    List<User> findByEmail(String email);

    Optional<User> findByEmailAndAuthProvider(String email, AuthProvider authProvider);
    
    
}
