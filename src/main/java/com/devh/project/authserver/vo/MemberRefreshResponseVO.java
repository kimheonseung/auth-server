package com.devh.project.authserver.vo;

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
public class MemberRefreshResponseVO {
	private TokenVO token;
//	public MemberRefreshResponseVO(TokenVO tokenVO) {
//		this.token = tokenVO;
//	}
}
