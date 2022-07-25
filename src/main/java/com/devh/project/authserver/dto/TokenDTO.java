package com.devh.project.authserver.dto;

import com.devh.project.authserver.constant.TokenStatus;
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
public class TokenDTO {
    private TokenStatus tokenStatus;
    private String accessToken;
    private String refreshToken;
}
