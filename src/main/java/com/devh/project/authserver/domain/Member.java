package com.devh.project.authserver.domain;

import java.io.Serializable;
import java.util.HashSet;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.devh.project.authserver.session.UserDetailsImpl;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

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
    
    public UserDetails toUserDetails() {
    	return UserDetailsImpl.builder()
    			.id(id)
    			.email(email)
    			.name(name)
    			.password(password)
    			.authorities(new HashSet<GrantedAuthority>())
    			.build();
    }
}
