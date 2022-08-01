package com.devh.project.authserver.login.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

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
public class LoginRequestDTO {
	@Email(message = "Not Valid Email")
	private String email;
	@NotBlank(message = "Password is mandatory")
	private String password;
}
