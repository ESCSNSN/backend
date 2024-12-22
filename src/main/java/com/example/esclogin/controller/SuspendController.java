package com.example.esclogin.controller;

import com.example.esclogin.dto.UserSuspendDTO;
import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.example.esclogin.jwt.JWTUtil;



@RestController
@RequiredArgsConstructor
@RequestMapping("/api/suspend")
public class SuspendController {

    private final UserService userService;
    private final JWTUtil jwtUtil;
    private static final Logger logger = LoggerFactory.getLogger(SuspendController.class);

    /**
     * 사용자 정지/정지 해제 API
     *
     * @param suspendDTO 사용자 정지 정보 DTO
     * @return 성공 메시지
     */
    @PostMapping("/user/suspend")
    public ResponseEntity<String> suspendUser(@Valid @RequestBody UserSuspendDTO suspendDTO, @RequestHeader("Authorization") String authorizationHeader) {
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
        String role = jwtUtil.getRole(token);
        logger.debug("Current username from token: {}", role);

        if (!role.equals("admin")) {
            logger.warn("Unauthorized access.");
            return ResponseEntity.status(403).body("Unauthorized access.");
        }

        try {
            userService.suspendUser(suspendDTO);
            if (Boolean.TRUE.equals(suspendDTO.getSuspend())) {
                return ResponseEntity.ok("사용자가 정지되었습니다.");
            } else {
                return ResponseEntity.ok("사용자 정지가 해제되었습니다.");
            }
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "사용자 정지 처리 중 오류가 발생했습니다.");
        }
    }

    /**
     * 현재 정지된 사용자 목록 조회
     *
     * @return 정지된 사용자 목록
     */
    @GetMapping("/users/suspended")
    public ResponseEntity<?> getSuspendedUsers(@RequestHeader("Authorization") String authorizationHeader) {
        // 1. Authorization 헤더 검사
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.warn("Authorization header missing or invalid.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization header missing or invalid.");
        }

        // 2. 토큰 추출
        String token = authorizationHeader.substring(7);
        logger.debug("Extracted token: {}", token);

        // 3. 토큰 유효성 검증 (JWTUtil 사용)
        boolean isValid = jwtUtil.validateToken(token);
        logger.debug("Token valid: {}", isValid);

        if (!isValid) {
            logger.warn("Invalid or expired token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token.");
        }

        // 4. 권한(ROLE) 확인
        String role = jwtUtil.getRole(token);
        logger.debug("Role from token: {}", role);

        if (!"admin".equalsIgnoreCase(role)) {
            logger.warn("Unauthorized access (not admin).");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized access.");
        }

        // 5. 정지된 사용자 목록 조회 로직
        try {
            List<UserEntity> suspendedUsers = userService.getSuspendedUsers();
            return ResponseEntity.ok(suspendedUsers);
        } catch (Exception e) {
            logger.error("Failed to get suspended users. Error: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "정지된 사용자 목록 조회 중 오류가 발생했습니다.");
        }
    }

}
