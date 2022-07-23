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

        String content =
                "<h1>title</h1>" +
                "<p>아래 링크를 클릭하여 회원 가입을 완료하세요.</p>" +
                "<p>http://127.0.0.1:8888/member/signup/complete?email=aaa&authKey=bbb</p>";

        mailMessage.setText(content);
        mailService.sendEmail(mailMessage);
    }
}
