package com.devh.project.authserver.vo;

import com.devh.project.authserver.constant.TokenStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class TokenVO {
    private TokenStatus tokenStatus;
    private String accessToken;
    private String refreshToken;
}
