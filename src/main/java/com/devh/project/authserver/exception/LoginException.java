package com.devh.project.authserver.exception;

public class LoginException extends IllegalStateException {
    public LoginException(String message) {
        super(message);
    }
}
