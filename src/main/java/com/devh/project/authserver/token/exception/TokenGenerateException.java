package com.devh.project.authserver.token.exception;

public class TokenGenerateException extends IllegalStateException {
	private static final long serialVersionUID = -9081748788090550473L;

	public TokenGenerateException(String message) {
        super(message);
    }
}
