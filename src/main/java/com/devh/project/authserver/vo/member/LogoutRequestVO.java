package com.devh.project.authserver.vo.member;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;

@Getter
@NoArgsConstructor
@ToString
public class LogoutRequestVO {
    @Email(message = "Not Valid Email")
    private String email;
    
    public LogoutRequestVO(String email) {
    	this.email = email;
    }
}
