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

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/suspend")
public class SuspendController {

    private final UserService userService;

    /**
     * 사용자 정지/정지 해제 API
     *
     * @param suspendDTO 사용자 정지 정보 DTO
     * @return 성공 메시지
     */
    @PostMapping("/user/suspend")
    public ResponseEntity<String> suspendUser(@Valid @RequestBody UserSuspendDTO suspendDTO) {
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
    public ResponseEntity<List<UserEntity>> getSuspendedUsers() {
        List<UserEntity> suspendedUsers = userService.getSuspendedUsers();
        return ResponseEntity.ok(suspendedUsers);
    }
}
