package com.example.Registration_Login.exception;

public class CustomException extends RuntimeException {
    private final int errorCode;

    public CustomException(String message) {
        super(message);
        this.errorCode = 0;
    }

    public CustomException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
