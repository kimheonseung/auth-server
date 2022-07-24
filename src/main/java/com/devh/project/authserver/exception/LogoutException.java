package com.devh.project.authserver.exception;

public class LogoutException extends IllegalStateException {
    public LogoutException(String message) {
        super(message);
    }
}
