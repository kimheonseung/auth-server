package com.devh.project.authserver.exception;

public class LogoutException extends IllegalStateException {
	private static final long serialVersionUID = -8045445312007929529L;

	public LogoutException(String message) {
        super(message);
    }
}
