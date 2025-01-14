package com.example.Registration_Login.controller;

import java.io.IOException;
import java.net.URI;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.Registration_Login.model.User;
import com.example.Registration_Login.service.UserService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class AuthController {
    
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody @Validated User user) {
        return ResponseEntity.ok(userService.registerUserLocal(user));
    }

    @PostMapping("/login/local")
    public ResponseEntity<User> loginLocal(@RequestBody User user) {

        return ResponseEntity.ok(userService.loginUserLocal(user));
    }

    @GetMapping("/login/{provider}")
    public ResponseEntity<String> loginAuth(@PathVariable String provider, HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/" + provider);
        return ResponseEntity.ok("Redirection ..");
    }

    @GetMapping("/loginSuccess/{provider}")
    public ResponseEntity<String> handleLoginSuccess(@PathVariable String provider, OAuth2AuthenticationToken oAuth2AuthenticationToken) throws IOException {

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
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create("http://localhost:3000/home")).build();
    }

        @RequestMapping("/sessionExpired")
        @ResponseBody
        public String sessionExpired() {
            return "Your session has expired. Please log in again.";
        }
}

