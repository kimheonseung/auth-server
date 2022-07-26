package com.devh.project.authserver.token.exception;

public class TokenNotFoundException extends IllegalArgumentException {
	private static final long serialVersionUID = -5938104993227201367L;
	
	public TokenNotFoundException() {
		super("Token not found for current member.");
	}
	public TokenNotFoundException(String message) {
		super(message);
	}
}
