package com.devh.project.authserver.helper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthKeyHelper {
	@Value("${auth.key.size}")
	private int keySize;
	@Autowired
	private SecureRandomHelper secureRandomHelper;
	
	public String generateAuthKey() {
		StringBuffer sbAuthKey = new StringBuffer();
		while(sbAuthKey.length() < this.keySize) {
			sbAuthKey.append(this.secureRandomHelper.getRandomInteger(10));
		}
		return sbAuthKey.toString();
	}
}
