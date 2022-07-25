package com.devh.project.authserver.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BCryptUtils {
	private final BCryptPasswordEncoder bcryptPasswordEncoder;
	
	public BCryptUtils() {
		this.bcryptPasswordEncoder = new BCryptPasswordEncoder();
	}
	
	public String encode(String rawString) {
		return this.bcryptPasswordEncoder.encode(rawString);
	}
	
	public boolean matches(String rawString, String encodedString) {
		return this.bcryptPasswordEncoder.matches(rawString, encodedString);
	}
}
