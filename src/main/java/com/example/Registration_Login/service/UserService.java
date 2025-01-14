package com.example.Registration_Login.service;

import com.example.Registration_Login.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.Registration_Login.enums.AuthProvider;
import com.example.Registration_Login.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUserLocal(User user) {

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("Email đã tồn tại trong hệ thống. Không thể đăng ký thêm.");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setAuthProvider(AuthProvider.LOCAL);
        return userRepository.save(user);
    }

    public User loginUserLocal(User user) {
        
        User exitingUser = userRepository.findByEmailAndPhonenumber(user.getEmail(), user.getPhonenumber())
            .orElse(null);
        if (exitingUser != null) {
            
            if (!passwordEncoder.matches(user.getPassword(), exitingUser.getPassword())) {
                
                throw new RuntimeException("User password does not match");
            }
            return exitingUser;
        }

        throw new RuntimeException("User not found");
    }

    public User loginRegisterByGoogleOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {

        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        log.info("USER EMAIL FROM GOOGLE IS {}", email);
        log.info("USER NAME FROM GOOGLE IS {}", name);

        User user = userRepository.findByEmailAndAuthProvider(email, AuthProvider.LOCAL).orElse(null);

        if (user != null) {
            user.setAuthProvider(AuthProvider.GOOGLE);
            return userRepository.save(user);
        } else {
            user = new User();
            user.setEmail(email);
            user.setName(name);
            user.setAuthProvider(AuthProvider.GOOGLE);
            userRepository.save(user);
        }
        
        return user;
        
    }

    public User loginRegisterByFacebookOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {

        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");

        log.info("USER EMAIL FROM FACEBOOK IS {}", email);
        log.info("USER NAME FROM FACEBOOK IS {}", name);

        User user = userRepository.findByEmail(email)
                .filter(u -> u.getAuthProvider().equals(AuthProvider.FACEBOOK))
                .orElse(null);
        if (user != null) {
            return user;
        }

        user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setAuthProvider(AuthProvider.FACEBOOK);

        return userRepository.save(user);
    }

    public User loginRegisterByGithubOauth2(OAuth2AuthenticationToken auth2AuthenticationToken) {

        OAuth2User oauth2User = auth2AuthenticationToken.getPrincipal();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("login");

        log.info("USER EMAIL FROM GITHUB IS {}", email);
        log.info("USER LOGIN NAME FROM GITHUB IS {}", name);

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            user = new User();
            user.setName(name);
            user.setEmail(email);
            user.setAuthProvider(AuthProvider.GITHUB);
            return userRepository.save(user);
        }

        return user;
    }

}
