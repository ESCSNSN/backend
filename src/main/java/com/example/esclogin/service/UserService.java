package com.example.esclogin.service;

import com.example.esclogin.dto.UserSuspendDTO;
import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // PasswordEncoder 빈 주입
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);


    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void suspendUser(UserSuspendDTO suspendDTO){
        String username = suspendDTO.getUsername();
        UserEntity user = userRepository.findByUsername(username);
        if (user == null){
            logger.error("정지하려는 사용자가 존재하지 않습니다. {}", username);
            throw new IllegalArgumentException("사용자가 존재하지 않습니다.");
        }

        if (suspendDTO.getSuspend()){
            user.setSuspended(true);
            user.setSuspendedUntil(suspendDTO.getSuspendedUntil());
            user.setSuspendReason(suspendDTO.getReason());
            logger.info("사용자가 정지되었습니다. {}", username, suspendDTO.getReason());
        } else {
            user.setSuspended(false);
            user.setSuspendedUntil(null);
            logger.info("사용자가 정지 해제되었습니다. {}", username);
        }
        userRepository.save(user);
    }

    public List<UserEntity> getSuspendedUsers(){
        return userRepository.findByIsSuspendedTrue();
    }

    public UserEntity getUserByUsername(String username){
        UserEntity user = userRepository.findByUsername(username);
        if (user == null){
            logger.error("사용자를 찾을 수 없습니다: {}", username);
            throw new IllegalArgumentException("사용자를 찾을 수 없습니다.");
        }
        return user;
    }

    @Transactional
    public void autoUnblockUsers() {
        LocalDateTime now = LocalDateTime.now();
        List<UserEntity> usersToUnblock = userRepository.findByIsSuspendedTrue();

        for (UserEntity user : usersToUnblock) {
            if (user.getSuspendedUntil() != null && user.getSuspendedUntil().isBefore(now)) {
                user.setSuspended(false);
                user.setSuspendedUntil(null);
                logger.info("자동으로 사용자의 정지가 해제되었습니다: {}", user.getUsername());
            }
        }
        // 변경 사항 저장
        userRepository.saveAll(usersToUnblock);
    }

    // 비밀번호 업데이트 메서드
    public boolean updatePassword(String email, String newPassword) {

        Optional<UserEntity> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return false; // 또는 예외
        }

        UserEntity user = optionalUser.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return true;
    }
    // 이메일으로 사용자 조회 메서드
    public Optional<UserEntity> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // 사용자 저장 메서드
    public void saveUser(UserEntity user) {
        userRepository.save(user);
    }

    public boolean updateEmail(String username, String newEmail) {
        Optional<UserEntity> optionalUser = findByUsername(username);
        if (optionalUser.isPresent()) {
            UserEntity user = optionalUser.get();
            user.setEmail(newEmail);
            userRepository.save(user);
            return true;
        }
        return false;
    }

    public Optional<UserEntity> findByUsername(String username) {
        return Optional.ofNullable(userRepository.findByUsername(username));
    }
}

