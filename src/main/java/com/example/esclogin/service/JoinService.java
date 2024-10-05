package com.example.esclogin.service;

import com.example.esclogin.dto.JoinDTO;
import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();
        String email = joinDTO.getEmail();
        String name = joinDTO.getName();

        // 사용자 이름 유효성 검사 (9자리)
        if (username == null || username.length() != 9) {
            throw new IllegalArgumentException("Username must be exactly 9 characters long.");
        }

        // 비밀번호 유효성 검사 (8~20자의 영어, 숫자, 특수문자 혼용)
        String passwordPattern = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,20}$";
        if (password == null || !Pattern.matches(passwordPattern, password)) {
            throw new IllegalArgumentException("Password must be 8-20 characters long and include letters, numbers, and special characters.");
        }

        // 이메일 유효성 검사
        String emailPattern = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        if (email == null || !Pattern.matches(emailPattern, email)) {
            throw new IllegalArgumentException("Invalid email format.");
        }

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setEmail(email);
        data.setName(name);
        data.setRole("tmp");

        userRepository.save(data);
    }
}