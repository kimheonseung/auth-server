package com.devh.project.authserver.domain;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.io.Serializable;

@Entity
@Builder
@Getter
@NoArgsConstructor
@EqualsAndHashCode(of = {"id", "email"})
@ToString
public class Member implements Serializable {
	private static final long serialVersionUID = -2158602508448402581L;
	@Id @GeneratedValue
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    private String name;
    private String password;

    public Member(Long id, String email, String name, String password) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.password = password;
    }
}
