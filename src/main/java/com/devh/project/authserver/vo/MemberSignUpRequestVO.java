package com.devh.project.authserver.vo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Getter
@NoArgsConstructor
@ToString
public class MemberSignUpRequestVO {
    @Email(message = "Not Valid Email")
    private String email;
    @NotBlank(message = "Name is mandatory")
    private String name;
    @NotBlank(message = "Password is mandatory")
    private String password;
    public MemberSignUpRequestVO(String email, String name, String password) {
        this.email = email;
        this.name = name;
        this.password = password;
    }
}
