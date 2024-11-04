package com.example.esclogin.controller;
import com.example.esclogin.dto.JoinDTO;
import com.example.esclogin.jwt.TemporaryJWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import com.example.esclogin.service.JoinService;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Controller
@ResponseBody
public class joinController {

    private final JoinService joinService;
    private final TemporaryJWTUtil temporaryJWTToken;
    public joinController(JoinService joinService, TemporaryJWTUtil temporaryJWTToken) {
        this.joinService = joinService;
        this.temporaryJWTToken = temporaryJWTToken;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO, @RequestHeader("Authorization") String authorizationHeader) {
        System.out.println(joinDTO.getUsername());
        // "Bearer " 접두사를 제거하여 실제 토큰 추출
        String temporaryJWTToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            temporaryJWTToken = authorizationHeader.substring(7);
        }

        if (temporaryJWTToken == null || temporaryJWTToken.isEmpty()) {
            throw new IllegalArgumentException("Authorization header missing or invalid.");
        }
        joinService.joinProcess(joinDTO, temporaryJWTToken); // 수정된 코드

        return "ok";
    }
}