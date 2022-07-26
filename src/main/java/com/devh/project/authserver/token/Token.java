package com.devh.project.authserver.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Token {
    private TokenStatus tokenStatus;
    private String accessToken;
    private String refreshToken;
    
    public static Token buildAccessTokenNotExpired(String accessToken, String refreshToken) {
    	return Token.builder()
    			.tokenStatus(TokenStatus.ACCESS_TOKEN_NOT_EXPIRED)
    			.accessToken(accessToken)
    			.refreshToken(refreshToken)
    			.build();
    }
    public static Token buildRefreshSuccess(String accessToken, String refreshToken) {
    	return Token.builder()
    			.tokenStatus(TokenStatus.REFRESH_SUCCESS)
    			.accessToken(accessToken)
    			.refreshToken(refreshToken)
    			.build();
    }
    public static Token buildRefreshFail() {
    	return buildNullByTokenStatus(TokenStatus.REFRESH_FAIL);
    }
    public static Token buildLoginRequired() {
    	return buildNullByTokenStatus(TokenStatus.LOGIN_REQUIRED);
    }
    public static Token buildInvalid() {
    	return buildNullByTokenStatus(TokenStatus.INVALID);
    }
    
    private static Token buildNullByTokenStatus(TokenStatus tokenStatus) {
    	return Token.builder()
    			.tokenStatus(tokenStatus)
    			.accessToken(null)
    			.refreshToken(null)
    			.build();
    }
}
