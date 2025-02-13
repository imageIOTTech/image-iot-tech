package com.example.Registration_Login.service;

import com.example.Registration_Login.model.User;

import java.util.Collections;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.Registration_Login.dto.LoginRequestDTO;
import com.example.Registration_Login.dto.UserRequestDTO;
import com.example.Registration_Login.enums.AuthProvider;
import com.example.Registration_Login.enums.Role;
import com.example.Registration_Login.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUserLocal(Object userObject) {

        User user;

        if (userObject instanceof UserRequestDTO) {
            UserRequestDTO userRequestDTO = (UserRequestDTO) userObject;
            user = new User();
            user.setName(userRequestDTO.getName());
            user.setEmail(userRequestDTO.getEmail());
            user.setPhonenumber(userRequestDTO.getPhonenumber());
            user.setPassword(userRequestDTO.getPassword());
            user.setAuthProvider(AuthProvider.LOCAL);
            user.setRoles(Collections.singleton(Role.USER));
        
        } else if (userObject instanceof User) {

            user = (User) userObject;
        } else {

            throw new IllegalArgumentException("Invalid user object type");
        }

        List<User> existingUsers = userRepository.findByEmail(user.getEmail());

        for (User existingUser : existingUsers) {

            if (existingUser.getAuthProvider() == AuthProvider.GOOGLE
                    || existingUser.getAuthProvider() == AuthProvider.LOCAL) {
                throw new RuntimeException(
                        "Email đã tồn tại trong hệ thống với Google hoặc Local. Không thể đăng ký thêm.");
            }
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setAuthProvider(AuthProvider.LOCAL);
        user.setRoles(Collections.singleton(Role.USER));
        return userRepository.save(user);
    }

    public User loginUserLocal(LoginRequestDTO loginRequestDTO) {
        List<User> users = userRepository.findByEmail(loginRequestDTO.getEmail());
        if (users.isEmpty()) {
            throw new RuntimeException("User not found with email: " + loginRequestDTO.getEmail());
        }
        User user = users.get(0);
        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        return user;
    }

    public User findByEmail(String email) {
        List<User> users = userRepository.findByEmail(email);
        if (users.isEmpty()) {
            throw new RuntimeException("User not found with email: " + email);
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
        userRepository.save(newUser);

        return newUser;
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
        userRepository.save(user);

        return user;
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
