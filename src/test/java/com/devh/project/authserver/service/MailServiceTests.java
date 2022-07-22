package com.devh.project.authserver.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {"spring.config.location=classpath:application-test.yml"})
public class MailServiceTests {
    @Autowired
    private MailService mailService;

    @Test
    public void test() {
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo("tjfdkrgjstmd@naver.com");
        mailMessage.setSubject("test");
        mailMessage.setText("message !");
        mailService.sendEmail(mailMessage);
    }
}
