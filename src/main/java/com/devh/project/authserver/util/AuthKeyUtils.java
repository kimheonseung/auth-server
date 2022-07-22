package com.devh.project.authserver.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthKeyUtils {
	@Value("${auth.key.size}")
	private int keySize;
	@Autowired
	private SecureRandomUtils secureRandomUtils;
	
	public String generateAuthKey() {
		StringBuffer sbAuthKey = new StringBuffer();
		while(sbAuthKey.length() < this.keySize) {
			sbAuthKey.append(this.secureRandomUtils.getRandomInteger(10));
		}
		return sbAuthKey.toString();
	}
}
