package com.devh.project.authserver.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

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
		assertTrue(authKey.length() == 16);
	}
}
