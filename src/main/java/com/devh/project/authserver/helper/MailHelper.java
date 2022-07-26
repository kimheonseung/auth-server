package com.devh.project.authserver.helper;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MailHelper {
    private final JavaMailSender javaMailSender;

    @Async
    public void sendSignupValidationMail(String email, String authKey) {
        javaMailSender.send(createSimpleMailMessageByEmailAndAuthKey(email, authKey));
    }

    private SimpleMailMessage createSimpleMailMessageByEmailAndAuthKey(String email, String authKey) {
        final String url = String.format("http://127.0.0.1:8888/signup/complete?email=%s&authKey=%s", email, authKey);
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setTo(email);
        simpleMailMessage.setSubject("회원가입 인증 확인 메일입니다.");
        simpleMailMessage.setText("다음 링크를 클릭하여 회원가입을 완료하세요. \n"+url);
        return simpleMailMessage;
    }
}
