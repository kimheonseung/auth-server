package com.devh.project.authserver.exception;

public class PasswordException extends IllegalStateException {
	private static final long serialVersionUID = 8686588820218936824L;

	public PasswordException(String message) {
        super(message);
    }
}
