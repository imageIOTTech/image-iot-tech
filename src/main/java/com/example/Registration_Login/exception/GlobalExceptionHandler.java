package com.example.Registration_Login.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<Map<String, Object>> handleCustomException(CustomException ex) {
        int errorCode = ex.getErrorCode();
        HttpStatus status = HttpStatus.BAD_REQUEST;
        if (errorCode == 401) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (errorCode == 404) {
            status = HttpStatus.NOT_FOUND;
        } else if (errorCode == 409) {
            status = HttpStatus.CONFLICT;
        }

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("message", ex.getMessage());
        errorBody.put("errorCode", errorCode);

        return ResponseEntity.status(status).body(errorBody);
    }
}
