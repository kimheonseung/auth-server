package com.devh.project.common.dto;

import com.devh.project.common.constant.ApiStatus;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * Description :
 *     API 응답 클래스
 * ===============================================
 * Member fields :
 *     timestamp
 *     status
 *     message
 *     description
 *     dataArray
 *     paging
 * ===============================================
 *
 * Author : HeonSeung Kim
 * Date   : 2022. 7. 14.
 * </pre>
 */
@Builder
@Getter
public class ApiResponseDTO<T> {
    private LocalDateTime timestamp;
    private int status;
    private String message;
    private String description;
    private List<T> dataArray;
    private PagingDTO paging;

    public static <T> ApiResponseDTO<T> success(ApiStatus.Success status) {
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(status.getDescription())
                .build();
    }

    public static <T> ApiResponseDTO<T> success(ApiStatus.Success status, List<T> dataArray) {
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(status.getDescription())
                .dataArray(dataArray)
                .build();
    }

    public static <T> ApiResponseDTO<T> success(ApiStatus.Success status, List<T> dataArray, PagingDTO pagingDTO) {
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(status.getDescription())
                .paging(pagingDTO)
                .dataArray(dataArray)
                .build();
    }

    public static <T> ApiResponseDTO<T> success(ApiStatus.Success status, T data) {
        List<T> dataArray = new ArrayList<>();
        dataArray.add(data);
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(status.getDescription())
                .dataArray(dataArray)
                .build();
    }

    public static <T> ApiResponseDTO<T> authError(ApiStatus.AuthError status) {
    	return ApiResponseDTO.<T>builder()
    			.timestamp(LocalDateTime.now())
    			.status(status.getCode())
    			.message(status.getStatus())
    			.description(status.getDescription())
    			.build();
    }
    
    public static <T> ApiResponseDTO<T> serverError(ApiStatus.ServerError status, String stacktrace) {
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(stacktrace)
                .build();
    }

    public static <T> ApiResponseDTO<T> customError(ApiStatus.CustomError status, String stacktrace) {
        return ApiResponseDTO.<T>builder()
                .timestamp(LocalDateTime.now())
                .status(status.getCode())
                .message(status.getStatus())
                .description(stacktrace)
                .build();
    }
}