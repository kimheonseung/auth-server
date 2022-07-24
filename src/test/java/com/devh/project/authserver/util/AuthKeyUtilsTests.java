package com.devh.project.authserver.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class AuthKeyUtilsTests {
	@InjectMocks
	AuthKeyUtils authKeyUtils;
	
	@BeforeEach
    public void beforeEach() throws NoSuchAlgorithmException {
        ReflectionTestUtils.setField(authKeyUtils, "keySize", 16);
        ReflectionTestUtils.setField(authKeyUtils, "secureRandomUtils", new SecureRandomUtils());
    }
	
	@Test
	public void generateAuthKey() {
		// when
		String authKey = authKeyUtils.generateAuthKey();
		// then
		assertEquals(authKey.length(), 16);
	}
}
