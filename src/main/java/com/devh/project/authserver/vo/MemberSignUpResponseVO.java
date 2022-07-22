package com.devh.project.authserver.vo;

import com.devh.project.authserver.constant.SignUpStatus;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@NoArgsConstructor
@ToString
public class MemberSignUpResponseVO {
    private SignUpStatus signUpStatus;
    private String email;
    @Builder
    public MemberSignUpResponseVO(SignUpStatus signUpStatus, String email) {
        this.signUpStatus = signUpStatus;
        this.email = email;
    }
}
