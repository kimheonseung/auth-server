package com.devh.project.authserver.vo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;

@Getter
@NoArgsConstructor
@ToString
public class MemberLogoutRequestVO {
    @Email(message = "Not Valid Email")
    private String email;
}
