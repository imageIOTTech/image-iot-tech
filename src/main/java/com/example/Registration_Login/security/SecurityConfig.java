package com.example.Registration_Login.security;

import java.beans.JavaBean;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(requests -> requests
                .requestMatchers("/register", "/login/**", "/logout").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2 
            .loginPage("/login/google")
            .successHandler((request, response, authentication) -> {
                OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
                String provider = token.getAuthorizedClientRegistrationId();
                String redirectUrl = "/loginSuccess/" + provider;
                response.sendRedirect(redirectUrl);
            })
                .failureUrl("/loginFailure"))
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login/local") 
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll())
            .sessionManagement(session -> session
                .invalidSessionUrl("/sessionExpired") 
                .maximumSessions(1)
                .expiredUrl("/sessionExpired"));
        
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder(); 
   }
}
