package com.devh.project.authserver.constant;

public enum TokenStatus {
    INVALID,
    REFRESH_SUCCESS,
    REFRESH_FAIL,
    LOGIN_REQUIRED,
    LOGIN_SUCCESS,
    ACCESS_TOKEN_NOT_EXPIRED;
}
