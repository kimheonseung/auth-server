package com.devh.project.authserver.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class BCryptUtilsTests {
	@InjectMocks
	BCryptUtils bcryptUtils;
	
	@Test
	public void encode() {
		// given
		final String givenRawString = "test";
		// when
		String encodedString = this.bcryptUtils.encode(givenRawString);
		// then
		System.out.println(encodedString);
	}
	
	@Test
	public void matches() {
		// given
		final String givenRawString = "test";
		final String givenEncodedString = "$2a$10$XOzzm0y.T5QU6Reb6TUyUusBodpFNzcHJEYUZ0YikF3bF9h7ZMsdO";
		// when
		boolean matches = this.bcryptUtils.matches(givenRawString, givenEncodedString);
		// then
		assertTrue(matches);
	}

}
