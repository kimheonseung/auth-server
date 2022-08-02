package com.devh.project.authserver.security.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.devh.project.authserver.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Component
@Slf4j
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	private final MemberRepository memberRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.info("findByEmail... "+username);
		return memberRepository
				.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException(username))
				.toUserDetails();
	}
}
