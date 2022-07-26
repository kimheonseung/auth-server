package com.devh.project.authserver.token.exception;

public class TokenRefreshException extends IllegalStateException {
	private static final long serialVersionUID = -6540628590785791333L;

	public TokenRefreshException(String message) {
		super(message);
	}
}
