package com.devh.project.authserver.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SecureRandomUtilsTests {
	@InjectMocks
	private SecureRandomUtils secureRandomUtils;
	
	@Test
	public void getRandomInteger() {
		// given
		final int givenMax = 10;
		// when
		int i = secureRandomUtils.getRandomInteger(givenMax);
		// then
		assertTrue(i < givenMax);
		assertTrue(i >= 0);
	}
}
