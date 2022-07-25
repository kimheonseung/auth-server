package com.devh.project.authserver.exception;

public class LoginException extends IllegalStateException {
	private static final long serialVersionUID = -9081748788090550473L;

	public LoginException(String message) {
        super(message);
    }
}
