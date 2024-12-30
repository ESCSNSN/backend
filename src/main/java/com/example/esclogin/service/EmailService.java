package com.example.esclogin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    // HTML 이메일 보내는 메서드
    public void sendHtmlEmail(String to, String subject, String password, String templateName) throws MessagingException, IOException {
        // HTML 템플릿 읽기 및 데이터 삽입
        String htmlContent = readHtmlTemplate(templateName, password);

        // MimeMessage 객체 생성
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true); // HTML 형식으로 전송
        helper.setFrom("jangboss02@gmail.com"); // 발신자 이메일 주소 설정

        // 이메일 전송
        mailSender.send(message);
    }

    // HTML 템플릿 파일 읽기 및 데이터 삽입
    private String readHtmlTemplate(String templateName, String password) throws IOException {
        ClassPathResource resource = new ClassPathResource("templates/" + templateName);
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        // 동적으로 비밀번호 삽입
        return content.toString().replace("<password>", password);
    }


}
