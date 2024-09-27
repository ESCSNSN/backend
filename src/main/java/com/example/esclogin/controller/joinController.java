package com.example.esclogin.controller;
import com.example.esclogin.dto.JoinDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import com.example.esclogin.service.JoinService;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class joinController {

    private final JoinService joinService;

    public joinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {
        System.out.println(joinDTO.getUsername());
        joinService.joinProcess(joinDTO);
        return "ok";
    }
}
