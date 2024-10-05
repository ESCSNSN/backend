package com.example.esclogin.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class TemporaryJWTUtil {

    private SecretKey secretKey;
    private final long temporaryJwtExpirationInMs = 15 * 60 * 1000; // 15분

    public TemporaryJWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // 임시 토큰 생성 메서드
    public String generateTemporaryToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + temporaryJwtExpirationInMs);

        return Jwts.builder()
                .setSubject(email)
                .claim("purpose", "PASSWORD_CHANGE")
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰 검증 메서드
    public boolean validateTemporaryToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String purpose = claims.get("purpose", String.class);
            return "PASSWORD_CHANGE".equals(purpose) && !isExpired(claims);
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 이메일 추출 메서드
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // 토큰 만료 여부 확인
    private boolean isExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}
