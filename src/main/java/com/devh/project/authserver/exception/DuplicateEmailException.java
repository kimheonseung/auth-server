package com.devh.project.authserver.exception;

public class DuplicateEmailException extends IllegalStateException {
    public DuplicateEmailException(String message) {
        super(message);
    }
}
