package com.example.backend.config;

import com.example.backend.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.DispatcherType;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화
                .authorizeHttpRequests(authorize ->
                        authorize
                                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll() // FORWARD 타입 허용
                                .requestMatchers("/", "/auth/**", "/js/**", "/css/**", "/img/**", "/fontawesome-free-6.5.1-web/**").permitAll() // 메인 페이지 및 정적 자원에 대한 접근 허용
                                .anyRequest().authenticated() // 그 외의 요청은 인증 필요
                )
                .formLogin(formLogin ->
                        formLogin
                                .defaultSuccessUrl("/", true) // 로그인 성공 시 이동할 기본 URL
                                .permitAll() // 로그인 페이지는 모든 사용자에게 허용
                )
                .logout(logout ->
                        logout
                                .logoutUrl("/auth/logout") // 로그아웃 처리 URL
                                .logoutSuccessUrl("/auth/login-form") // 로그아웃 성공 후 이동할 URL
                                .permitAll()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 비밀번호 암호화를 위한 BCrypt 사용
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // CustomUserDetailsService 사용
        authProvider.setPasswordEncoder(passwordEncoder()); // 비밀번호 인코더 설정
        return authProvider;
    }
}
