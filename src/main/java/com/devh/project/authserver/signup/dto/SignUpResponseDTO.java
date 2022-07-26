package com.devh.project.authserver.signup.dto;

import com.devh.project.authserver.signup.SignUpStatus;

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
public class SignUpResponseDTO {
	private SignUpStatus signUpStatus;
	private String email;
}
