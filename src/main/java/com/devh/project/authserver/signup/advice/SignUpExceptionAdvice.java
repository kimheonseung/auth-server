package com.devh.project.authserver.signup.advice;

import com.devh.project.authserver.signup.exception.DuplicateEmailException;
import com.devh.project.authserver.signup.exception.PasswordException;
import com.devh.project.authserver.signup.exception.SignUpException;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class SignUpExceptionAdvice {
    @ExceptionHandler({DuplicateEmailException.class})
    public <T> ApiResponseDTO<T> handleDuplicateEmailException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.DUPLICATE_EMAIL_ERROR, e.getMessage());
    }
    @ExceptionHandler({PasswordException.class})
    public <T> ApiResponseDTO<T> handlePasswordException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.PASSWORD_ERROR, e.getMessage());
    }
    @ExceptionHandler({SignUpException.class})
    public <T> ApiResponseDTO<T> handleSignUpException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.SIGNUP_ERROR, e.getMessage());
    }
}
