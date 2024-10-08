package com.example.esclogin.service;

import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // PasswordEncoder 빈 주입

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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

