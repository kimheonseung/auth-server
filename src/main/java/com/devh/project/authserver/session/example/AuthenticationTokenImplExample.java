package com.devh.project.authserver.session.example;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticationTokenImplExample extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 6457163096489700114L;

	private String email;
	private String credentials;
	
	public AuthenticationTokenImplExample(String email, String credentials, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.email = email;
		this.credentials = credentials;
	}
	
	public AuthenticationTokenImplExample(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.email;
	}
	
}
