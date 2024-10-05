package com.example.esclogin.dto;

import lombok.Getter;
import lombok.Setter;


public class EmailRequest {
    private String email;

    // Getters and Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}