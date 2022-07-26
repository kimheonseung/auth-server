package com.devh.project.authserver.helper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.devh.project.authserver.helper.AuthKeyHelper;
import com.devh.project.authserver.helper.SecureRandomHelper;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AuthKeyHelperTests {
	@InjectMocks
	AuthKeyHelper authKeyHelper;
	
	@BeforeEach
    public void beforeEach() throws NoSuchAlgorithmException {
        ReflectionTestUtils.setField(authKeyHelper, "keySize", 16);
        ReflectionTestUtils.setField(authKeyHelper, "secureRandomUtils", new SecureRandomHelper());
    }
	
	@Test
	public void generateAuthKey() {
		// when
		String authKey = authKeyHelper.generateAuthKey();
		// then
		assertEquals(authKey.length(), 16);
	}
}
