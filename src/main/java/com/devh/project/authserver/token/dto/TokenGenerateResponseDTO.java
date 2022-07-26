package com.devh.project.authserver.token.dto;

import com.devh.project.authserver.token.Token;

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
public class TokenGenerateResponseDTO {
    private Token token;
}
