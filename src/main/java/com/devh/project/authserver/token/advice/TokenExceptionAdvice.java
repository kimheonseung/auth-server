package com.devh.project.authserver.token.advice;

import com.devh.project.authserver.token.exception.TokenException;
import com.devh.project.authserver.token.exception.TokenGenerateException;
import com.devh.project.authserver.token.exception.TokenInvalidateException;
import com.devh.project.authserver.token.exception.TokenRefreshException;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class TokenExceptionAdvice {
    @ExceptionHandler({TokenException.class})
    public <T> ApiResponseDTO<T> handleTokenException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.TOKEN_ERROR, e.getMessage());
    }
    @ExceptionHandler({TokenGenerateException.class})
    public <T> ApiResponseDTO<T> handleTokenGenerateException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.TOKEN_GENERATE_ERROR, e.getMessage());
    }
    @ExceptionHandler({TokenInvalidateException.class})
    public <T> ApiResponseDTO<T> handleTokenInvalidateException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.TOKEN_INVALIDATE_ERROR, e.getMessage());
    }
    @ExceptionHandler({TokenRefreshException.class})
    public <T> ApiResponseDTO<T> handleTokenRefreshException(Exception e) {
        return ApiResponseDTO.customError(ApiStatus.CustomError.TOKEN_REFRESH_ERROR, e.getMessage());
    }
}
