package com.example.esclogin.repository;

import com.example.esclogin.entity.UserEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    UserEntity findByUsername(String username);
    Optional findByEmail(String email);

    @Modifying
    @Transactional
    @Query("UPDATE UserEntity u SET u.refreshToken = :refreshToken WHERE u.username = :username")
    void updateRefreshToken(String username, String refreshToken);
}
