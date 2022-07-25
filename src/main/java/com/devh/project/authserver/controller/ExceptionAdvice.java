package com.devh.project.authserver.controller;

import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * <pre>
 * Description :
 *     API 수행 중 감지된 에러 핸들링
 * ===============================================
 * Member fields :
 *
 * ===============================================
 *
 * Author : HeonSeung Kim
 * Date   : 2022. 7. 14.
 * </pre>
 */
@RestControllerAdvice
public class ExceptionAdvice {
    @ExceptionHandler({MethodArgumentNotValidException.class})
    public <T> ApiResponseDTO<T> handleMethodArgumentNotValidException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.VALIDATION_ERROR, e.getMessage());
    }
    @ExceptionHandler({DuplicateEmailException.class})
    public <T> ApiResponseDTO<T> handleDuplicateEmailException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.DUPLICATE_EMAIL_ERROR, e.getMessage());
    }
    @ExceptionHandler({PasswordException.class})
    public <T> ApiResponseDTO<T> handlePasswordExceptionException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.PASSWORD_ERROR, e.getMessage());
    }
}