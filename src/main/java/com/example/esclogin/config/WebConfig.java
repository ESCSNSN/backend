package com.example.esclogin.config;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 모든 엔드포인트에 대해 CORS 설정
                .allowedOrigins("http://localhost:3000") // 프론트엔드 주소 (예: React 개발 서버)
                .allowedMethods("GET", "POST", "PUT", "DELETE") // 허용할 HTTP 메소드
                .allowedHeaders("Authorization", "Content-Type") // 허용할 헤더
                .allowCredentials(true); // 인증 정보를 포함한 요청 허용
    }
}

