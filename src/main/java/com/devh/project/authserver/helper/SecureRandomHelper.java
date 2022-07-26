package com.devh.project.authserver.helper;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.springframework.stereotype.Component;

@Component
public class SecureRandomHelper {
	private final Random random;

	public SecureRandomHelper() throws NoSuchAlgorithmException {
		this.random = SecureRandom.getInstanceStrong();
	}
	
	// 0 <= rand < max
	public int getRandomInteger(int max) {
		return this.random.nextInt(max);
	}
}
