package com.devh.project.authserver.signup.exception;

public class DuplicateEmailException extends IllegalStateException {
	private static final long serialVersionUID = 715362994553798061L;

	public DuplicateEmailException(String message) {
        super(message);
    }
}
