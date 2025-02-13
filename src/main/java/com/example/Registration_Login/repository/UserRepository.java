package com.example.Registration_Login.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.Registration_Login.model.User;
import java.util.List;
import com.example.Registration_Login.enums.AuthProvider;



public interface UserRepository extends JpaRepository<User, Long>{

    Optional<User> findByEmailAndPhonenumber(String email, Long phonenumber);

    List<User> findByEmail(String email);

    Optional<User> findByEmailAndAuthProvider(String email, AuthProvider authProvider);
    
    
}
