package com.example.esclogin.service;

import com.example.esclogin.dto.JoinDTO;
import com.example.esclogin.entity.UserEntity;
import com.example.esclogin.jwt.TemporaryJWTUtil;
import com.example.esclogin.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TemporaryJWTUtil temporaryJWTUtil;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, TemporaryJWTUtil temporaryJWTUtil) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.temporaryJWTUtil = temporaryJWTUtil;
    }

    public void joinProcess(JoinDTO joinDTO, String temporaryToken) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();
        String email = joinDTO.getEmail();
        String name = joinDTO.getName();
        String role = joinDTO.getRole();

        if(!temporaryJWTUtil. validateTemporaryToken(temporaryToken)) {
            throw new IllegalArgumentException("Token is not valid.");
        }

        String tokenEmail = temporaryJWTUtil.getEmailFromToken(temporaryToken);
        if (!tokenEmail.equals(email)) {
            throw new IllegalArgumentException("Email in token does not match the provided email.");
        }

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
        String emailPattern = "^[A-Za-z0-9+_.-]+@inu\\.ac\\.kr$";
        if (email == null || !Pattern.matches(emailPattern, email)) {
            throw new IllegalArgumentException("Invalid email format.");
        }
        if (!"GRADUATE".equals(role) && !"STUDENT".equals(role)) {
            throw new IllegalArgumentException("Role must be either GRADUATE or STUDENT.");
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
        data.setRole(role);

        userRepository.save(data);
    }
}