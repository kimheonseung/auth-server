package com.devh.project.authserver.vo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Getter
@NoArgsConstructor
@ToString
public class MemberLoginRequestVO {
    @Email(message = "Not Valid Email")
    private String email;
    @NotBlank(message = "Password is mandatory")
    private String password;
    public MemberLoginRequestVO(String email, String password) {
        this.email = email;
        this.password = password;
    }
}
