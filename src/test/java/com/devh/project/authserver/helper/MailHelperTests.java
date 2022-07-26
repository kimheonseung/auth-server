package com.devh.project.authserver.helper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {"spring.config.location=classpath:application-test.yml"})
public class MailHelperTests {
    @Autowired
    private MailHelper mailHelper;

    @Test
    public void sendSignupValidationMail() {
    	// given
    	final String givenEmail = "tjfdkrgjstmd@naver.com";
    	final String authKey = "authKey";
    	// then
    	mailHelper.sendSignupValidationMail(givenEmail, authKey);
    }
}
