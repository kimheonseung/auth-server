package com.devh.project.authserver.exception;

public class TokenInvalidateException extends IllegalStateException {
	private static final long serialVersionUID = -8045445312007929529L;

	public TokenInvalidateException(String message) {
        super(message);
    }
}
