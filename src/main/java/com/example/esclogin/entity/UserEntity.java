package com.example.esclogin.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Setter
@Getter
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(unique = true)
    private String username;

    private String password;

    @Column(unique = true)
    private String email;

    private String name;
    private String role;
    private String refreshToken;
    private boolean isSuspended = false;
    private String suspendReason;
    private LocalDateTime suspendedUntil;
}
