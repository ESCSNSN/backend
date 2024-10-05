package com.example.esclogin.util;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    private static final String PASSWORD_PATTERN =
            "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,20}$";

    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    /**
     * 비밀번호의 유효성을 검사합니다.
     *
     * @param password 검증할 비밀번호
     * @throws IllegalArgumentException 비밀번호가 유효하지 않을 경우 예외를 던집니다.
     */
    public void validate(String password) {
        if (password == null || !pattern.matcher(password).matches()) {
            throw new IllegalArgumentException("Password must be 8-20 characters long and include letters, numbers, and special characters.");
        }
    }

    /**
     * 비밀번호의 유효성을 검사하여 boolean 값을 반환합니다.
     *
     * @param password 검증할 비밀번호
     * @return 비밀번호가 유효하면 true, 그렇지 않으면 false
     */
    public boolean isValid(String password) {
        return password != null && pattern.matcher(password).matches();
    }
}
