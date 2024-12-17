package com.example.esclogin.config;

import com.example.esclogin.jwt.JWTAuthorizationFilter;
import com.example.esclogin.jwt.JWTUtil;
import com.example.esclogin.jwt.LoginFilter;
import com.example.esclogin.jwt.TemporaryJWTUtil;
import com.example.esclogin.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private  final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final TemporaryJWTUtil temporaryJWTUtil;
    private final UserRepository userRepository;


    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil, TemporaryJWTUtil temporaryJWTUtil, UserRepository userRepository) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.temporaryJWTUtil = temporaryJWTUtil;

        this.userRepository = userRepository;
    }

    @Bean
    public HttpFirewall customHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(true);  // 예시로 다른 인코딩을 허용하는 설정
        // 필요하다면 다른 설정 추가
        return firewall;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    @Order(1) // 우선순위가 높은 순으로 설정
    public SecurityFilterChain registerEmailFilterChain(HttpSecurity http) throws Exception {
        JWTAuthorizationFilter jwtAuthorizationFilter = new JWTAuthorizationFilter(jwtUtil);

        http
                .securityMatcher("/api/auth/register-email", "/api/auth/confirm-email") // 특정 엔드포인트에만 적용

                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated() // 인증 필요
                )
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );
        http
                .csrf((auth) -> auth.disable());
        http
                .cors((cors) -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/api/auth/send-email", "/api/auth/**").permitAll()
                        .requestMatchers("/api/auth/refresh").permitAll() // Refresh Token 재발급 엔드포인트
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

        // LoginFilter에서 Access Token + Refresh Token 발급
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, userRepository),
                        UsernamePasswordAuthenticationFilter.class);

        http
                .formLogin(auth -> auth.disable())
                .httpBasic(auth -> auth.disable())
                .csrf(auth -> auth.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000","https://97c2-2001-2d8-e249-5492-f0c0-56ec-6533-774b.ngrok-free.app")); // 프론트엔드 주소
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 허용할 HTTP 메소드
        configuration.setAllowedHeaders(Arrays.asList("*")); // 허용할 헤더
        configuration.setExposedHeaders(Arrays.asList("Authorization")); // expose 할 헤더

        configuration.setAllowCredentials(true); // 인증 정보를 포함한 요청 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 엔드포인트에 적용
        return source;
    }
}