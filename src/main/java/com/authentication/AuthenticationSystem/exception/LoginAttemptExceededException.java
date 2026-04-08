package com.authentication.AuthenticationSystem.exception;

public class LoginAttemptExceededException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public LoginAttemptExceededException(String message) {
        super(message);
    }
}
