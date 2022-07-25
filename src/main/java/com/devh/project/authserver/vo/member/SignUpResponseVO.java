package com.devh.project.authserver.vo.member;

import com.devh.project.authserver.constant.SignUpStatus;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@NoArgsConstructor
@ToString
public class SignUpResponseVO {
	private SignUpStatus signUpStatus;
	private String email;

	@Builder
	public SignUpResponseVO(SignUpStatus signUpStatus, String email) {
		this.signUpStatus = signUpStatus;
		this.email = email;
	}
}
