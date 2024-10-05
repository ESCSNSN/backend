package com.example.esclogin.controller;

import com.example.esclogin.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.esclogin.jwt.TemporaryJWTUtil;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.http.HttpServletResponse;
import com.example.esclogin.util.PasswordValidator;
import com.example.esclogin.service.UserService;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final EmailService emailService;
    private final ConcurrentHashMap<String, String> emailCodeMap = new ConcurrentHashMap<>();
    private final TemporaryJWTUtil temporaryJWTUtil;
    private final PasswordValidator passwordValidator;
    private final UserService userService;


    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    @Autowired
    public AuthController(EmailService emailService, TemporaryJWTUtil TemporaryJWTUtil, PasswordValidator passwordValidator, UserService userService) {
        this.emailService = emailService;
        this.temporaryJWTUtil = TemporaryJWTUtil;
        this.passwordValidator = passwordValidator;
        this.userService = userService;
    }

    // @RequestBody 대신 @RequestParam으로 수정
    @PostMapping("/send-email")
    public ResponseEntity<String> sendEmail(@RequestParam String email) {
        System.out.println("Received email: " + email);

        // 6자리 인증 코드 생성
        String verificationCode = generateCode();

        // 생성된 코드와 이메일을 매핑하여 저장 (임시로 메모리에 저장, 실제로는 데이터베이스나 캐시를 사용)
        emailCodeMap.put(email, verificationCode);
        scheduler.schedule(() -> {
            emailCodeMap.remove(email);
            System.out.println("Verification code for " + email + " has expired and removed.");
        }, 15, TimeUnit.MINUTES);

        // 이메일 전송
        String subject = "Email Verification";
        String content = "Your verification code is: " + verificationCode;
        emailService.sendEmail(email, subject, content);

        return ResponseEntity.ok("Verification code sent to " + email);
    }

    // 6자리 랜덤 숫자 생성 메서드
    private String generateCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // 100000 ~ 999999
        return String.valueOf(code);
    }

    // 추가: 인증 코드 검증을 위한 엔드포인트 (선택 사항)
    @PostMapping("/verify-code")
    public ResponseEntity<String> verifyCode(@RequestParam String email, @RequestParam String code, HttpServletResponse response) {
        String storedCode = emailCodeMap.get(email);
        if (storedCode != null && storedCode.equals(code)) {
            // 인증 성공 로직
            emailCodeMap.remove(email); // 코드 사용 후 제거
            String temporaryToken = temporaryJWTUtil.generateTemporaryToken(email);
            response.addHeader("Authorization", "Bearer " + temporaryToken);
            return ResponseEntity.ok("Verification successful.");
        } else {
            return ResponseEntity.status(400).body("Invalid verification code.");
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(
            @RequestParam String newPassword,
            @RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        String token = authorizationHeader.substring(7);
        boolean isValid = temporaryJWTUtil.validateTemporaryToken(token);
        if (!isValid) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        //토큰에서 이메일 추출
        String email = temporaryJWTUtil.getEmailFromToken(token);

        try {
            // 비밀번호 강도 검증
            passwordValidator.validate(newPassword);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body("Invalid password: " + e.getMessage());

        }
        boolean isChanged = userService.updatePassword(email, newPassword);
        if (isChanged) {
            return ResponseEntity.ok("Password changed successfully.");
        } else {
            return ResponseEntity.status(500).body("Failed to change password.");
        }
    }
}

