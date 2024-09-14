package com.example.backend.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import com.example.backend.service.UserService;

@Controller
public class PasswordChangeController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public PasswordChangeController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/change-password")
    public String changePassword(String newPassword, String studentId) {
        String encodedPassword = passwordEncoder.encode(newPassword);
        userService.changePassword(studentId, encodedPassword);
        return "redirect:/home";
    }
}
