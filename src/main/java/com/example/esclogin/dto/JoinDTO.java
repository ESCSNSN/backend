package com.example.esclogin.dto;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinDTO {
    private String username;
    private String password;
    private String email;
    private String name;
    private String role;

    public String getRole(){
        return role;
    }
    public void setRole(String role){
        this.role = role;
    }
}
