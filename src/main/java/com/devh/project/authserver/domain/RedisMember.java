package com.devh.project.authserver.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@RedisHash(value = "member", timeToLive = 300)
@ToString
public class RedisMember {
	@Id
	private String email;
	private String name;
	private String password;
	private String authKey;
	
	@Builder
	public RedisMember(String email, String name, String password, String authKey) {
		this.email = email;
		this.name = name;
		this.password = password;
		this.authKey = authKey;
	}
}
