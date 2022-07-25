package com.devh.project.authserver.dto.member;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.validation.constraints.Email;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LogoutRequestDTO {
    @Email(message = "Not Valid Email")
    private String email;
}
