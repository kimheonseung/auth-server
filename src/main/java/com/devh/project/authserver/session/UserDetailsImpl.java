package com.devh.project.authserver.session;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class UserDetailsImpl implements UserDetails {

	private static final long serialVersionUID = 5847157464990380735L;

	private Long id;
	private String email;
	private String name;
	private String password;
	private Collection<? extends GrantedAuthority> authorities;
	
	// 권한 목록
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	// 비밀번호
	@Override
	public String getPassword() {
		return this.password;
	}

	// 식별값
	@Override
	public String getUsername() {
		return this.email;
	}

	// 계정 만료 여부
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 계정 잠김 여부
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 비밀번호 만료 여부
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	// 계정 활성 여부
	@Override
	public boolean isEnabled() {
		return true;
	}

}
