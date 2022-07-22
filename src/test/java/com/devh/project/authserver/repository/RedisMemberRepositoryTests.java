package com.devh.project.authserver.repository;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.redis.DataRedisTest;

import com.devh.project.authserver.domain.RedisMember;

@DataRedisTest
public class RedisMemberRepositoryTests {
	@Autowired
	private RedisMemberRepository redisMemberRepository;
	
	@BeforeEach
	public void beforeEach() {
		redisMemberRepository.deleteById("test@test.com");
		RedisMember defaultRedisMember = RedisMember.builder()
				.email("test@test.com")
				.name("test")
				.password("pw")
				.authKey("key")
				.build();
		redisMemberRepository.save(defaultRedisMember);
	}
	
	@Test
	public void save() {
		// given
		final String givenId = "test@test.com";
		RedisMember redisMember = RedisMember.builder()
				.email(givenId)
				.name("test")
				.password("tpw")
				.authKey("authKey")
			.build();
		redisMemberRepository.save(redisMember);
		// when
		RedisMember m = redisMemberRepository.findById(givenId).orElseThrow();
		// then
		assertEquals(m.getEmail(), redisMember.getEmail());
		assertEquals(m.getName(), redisMember.getName());
		assertEquals(m.getPassword(), redisMember.getPassword());
	}
	@Test
	public void findById() {
		// given
		final String givenId = "test@test.com";
		// when
		RedisMember m = redisMemberRepository.findById(givenId).orElseThrow();
		// then
		assertEquals(m.getEmail(), givenId);
	}
	@Test
	public void deleteById() {
		
	}
}
