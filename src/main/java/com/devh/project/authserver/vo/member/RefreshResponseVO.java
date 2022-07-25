package com.devh.project.authserver.vo.member;

import com.devh.project.authserver.vo.TokenVO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class RefreshResponseVO {
	private TokenVO token;
}
