package com.example.esclogin.controller;

import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.jwt.JWTUtil;
import com.example.esclogin.repository.UserRepository;
import com.example.esclogin.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.esclogin.jwt.TemporaryJWTUtil;

import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletResponse;
import com.example.esclogin.util.PasswordValidator;
import com.example.esclogin.service.UserService;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class); // Logger 초기화

    private final EmailService emailService;
    private final ConcurrentHashMap<String, String> emailCodeMap = new ConcurrentHashMap<>();
    private final TemporaryJWTUtil temporaryJWTUtil;
    private final PasswordValidator passwordValidator;
    private final UserService userService;
    private final UserRepository userRepository;
    private final ConcurrentHashMap<Long, String> emailRegisterCodeMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private final JWTUtil jwtUtil;

    @Autowired
    public AuthController(EmailService emailService, TemporaryJWTUtil TemporaryJWTUtil, PasswordValidator passwordValidator, UserService userService, UserRepository userRepository, JWTUtil jwtUtil) {
        this.emailService = emailService;
        this.temporaryJWTUtil = TemporaryJWTUtil;
        this.passwordValidator = passwordValidator;
        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (jwtUtil.validateToken(refreshToken)) {
            String username = jwtUtil.getUsername(refreshToken);
            UserEntity user = userRepository.findByUsername(username);

            // 서버에 저장된 Refresh Token과 일치하는지 확인
            if (user.getRefreshToken().equals(refreshToken)) {
                String newAccessToken = jwtUtil.createJwt(username, "ROLE_USER", 15 * 60 * 1000L);
                return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Refresh Token");
    }
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestParam("token") String token) {
        if (jwtUtil.validateToken(token)) {
            String username = jwtUtil.getUsername(token);
            UserEntity user = userRepository.findByUsername(username);

            // 검증 성공 시 반환
            return ResponseEntity.ok(Map.of(
                    "isValid", true,
                    "username", username,
                    "role", user.getRole()
            ));
        } else {
            // 검증 실패 시 반환
            return ResponseEntity.ok(Map.of("isValid", false));
        }
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
        if (storedCode != null /*&& storedCode.equals(code)*/) {
            // 인증 성공 로직
            emailCodeMap.remove(email); // 코드 사용 후 제거
            String temporaryToken = temporaryJWTUtil.generateTemporaryToken(email);
            response.addHeader("Authorization", "Bearer " + temporaryToken);
            return ResponseEntity.ok("Verification successful.");
        } else {
            return ResponseEntity.status(400).body("Invalid verification code.");
        }
    }

    @PostMapping("/register-email")
    public ResponseEntity<String> registerEmail(@RequestParam String newEmail,
                                                @RequestHeader("Authorization") String authorizationHeader) {
        // Authorization 헤더에서 토큰 추출

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.warn("Authorization header missing or invalid.");
            return ResponseEntity.status(401).body("Authorization header missing or invalid.");
        }

        String token = authorizationHeader.substring(7);
        logger.debug("Extracted token: {}", token);

        // JWTUtil을 사용하여 토큰 검증

        boolean isValid = jwtUtil.validateToken(token);
        logger.debug("Token valid: {}", isValid);

        if (!isValid) {
            logger.warn("Invalid or expired token.");
            return ResponseEntity.status(401).body("Invalid or expired token.");
        }

        // 토큰에서 username 추출
        String username = jwtUtil.getUsername(token);
        logger.debug("Current username from token: {}", username);

        // 사용자 조회
        Optional<UserEntity> optionalUser = userService.findByUsername(username);
        if (optionalUser.isEmpty()) {
            logger.warn("User not found for username: {}", username);
            return ResponseEntity.status(404).body("User not found.");
        }

        UserEntity user = optionalUser.get();

        // 이미 이메일이 등록되어 있는지 확인
        if (user.getEmail() != null && !user.getEmail().isEmpty()) {
            logger.warn("Email is already registered for user: {}", username);
            return ResponseEntity.status(400).body("Email is already registered.");
        }

        // 새로운 이메일로 인증 코드 생성 및 전송
        String verificationCode = generateCode();
        emailRegisterCodeMap.put((long) user.getId(), verificationCode);
        logger.debug("Generated verification code: {} for user ID: {}", verificationCode, user.getId());

        // 인증 코드 만료 설정 (15분 후 제거)
        scheduler.schedule(() -> {
            emailRegisterCodeMap.remove((long) user.getId());
            logger.info("Email registration verification code for user ID {} has expired and removed.", user.getId());
        }, 15, TimeUnit.MINUTES);

        // 이메일 전송
        String subject = "Email Registration Verification";
        String content = "Your email registration verification code is: " + verificationCode;
        emailService.sendEmail(newEmail, subject, content);
        logger.info("Verification code sent to {}", newEmail);

        return ResponseEntity.ok("Verification code sent to " + newEmail + " for email registration.");
    }

    @PostMapping("/confirm-email")
    public ResponseEntity<String> confirmEmail(@RequestParam String verificationCode, @RequestParam String email,
                                               @RequestHeader("Authorization") String authorizationHeader) {
        // Authorization 헤더에서 토큰 추출
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.warn("Authorization header missing or invalid.");
            return ResponseEntity.status(401).body("Authorization header missing or invalid.");
        }

        String token = authorizationHeader.substring(7);
        logger.debug("Extracted temporary token: {}", token);

        // TemporaryJWTUtil을 사용하여 토큰 검증
        boolean isValid = jwtUtil.validateToken(token);
        logger.debug("Temporary Token valid: {}", isValid);

        if (!isValid) {
            logger.warn("Invalid or expired temporary token.");
            return ResponseEntity.status(401).body("Invalid or expired token.");
        }

        // 토큰에서 email 추출
        String username = jwtUtil.getUsername(token);
        logger.debug("Username from token: {}", username);

        // 사용자 조회
        Optional<UserEntity> optionalUser = userService.findByUsername(username);
        if (optionalUser.isEmpty()) {
            logger.warn("User not found for username!: {}", username);
            return ResponseEntity.status(404).body("User not found.");
        }

        UserEntity user = optionalUser.get();

        // 인증 코드 확인
        String storedCode = emailRegisterCodeMap.get((long) user.getId());
        if (storedCode == null || !storedCode.equals(verificationCode)) {
            logger.warn("Invalid verification code for user ID: {}", (long) user.getId());
            return ResponseEntity.status(400).body("Invalid verification code.");
        }

        // 이메일 등록 로직
        user.setEmail(email);
        userService.saveUser(user);
        logger.info("Email {} has been successfully registered for user ID {}", email, (long)user.getId());

        // 인증 코드 제거
        emailRegisterCodeMap.remove((long)user.getId());

        return ResponseEntity.ok("Email has been successfully registered.");
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

