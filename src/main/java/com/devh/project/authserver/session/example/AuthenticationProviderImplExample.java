package com.devh.project.authserver.session.example;

import java.util.HashSet;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.devh.project.authserver.helper.AES256Helper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationProviderImplExample implements AuthenticationProvider {

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;
	private final AES256Helper aes256Helper;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final String username = authentication.getName();
		String password = (String) authentication.getCredentials();
		
		try {
			password = aes256Helper.decrypt(password);
		} catch (Exception e) {
			log.warn(e.getMessage());
		} 
		
		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
		
		if(!this.passwordEncoder.matches(password, userDetails.getPassword())) {
			throw new BadCredentialsException("password not matches.");
		}
		
		return new AuthenticationTokenImplExample(username, password, new HashSet<GrantedAuthority>());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthenticationTokenImplExample.class.isAssignableFrom(authentication);
	}

}
