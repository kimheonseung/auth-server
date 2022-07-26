package com.devh.project.authserver.token.service;

import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.signup.exception.PasswordException;
import com.devh.project.authserver.token.exception.TokenGenerateException;
import com.devh.project.authserver.token.exception.TokenInvalidateException;
import com.devh.project.authserver.token.exception.TokenNotFoundException;
import com.devh.project.authserver.token.exception.TokenRefreshException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.helper.JwtHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.token.Token;
import com.devh.project.authserver.token.dto.TokenGenerateRequestDTO;
import com.devh.project.authserver.token.dto.TokenGenerateResponseDTO;
import com.devh.project.authserver.token.dto.TokenInvalidateRequestDTO;
import com.devh.project.authserver.token.dto.TokenInvalidateResponseDTO;
import com.devh.project.authserver.token.dto.TokenRefreshRequestDTO;
import com.devh.project.authserver.token.dto.TokenRefreshResponseDTO;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class TokenService {

    private final AES256Helper aes256Helper;
    private final MemberRepository memberRepository;
    private final MemberTokenRepository memberTokenRepository;
    private final JwtHelper jwtHelper;
    private final BCryptHelper bcryptHelper;

    public TokenGenerateResponseDTO generateToken(TokenGenerateRequestDTO tokenGenerateRequestDTO) throws Exception {
		final String email = tokenGenerateRequestDTO.getEmail();
		final String password = aes256Helper.decrypt(tokenGenerateRequestDTO.getPassword());
		/* member check */
		Member member = memberRepository.findByEmail(email).orElseThrow(() -> new TokenGenerateException(email + " does not exists."));
		/* generate token */
		if(bcryptHelper.matches(password, member.getPassword())) {
			Token token = jwtHelper.generateTokenByEmail(email);
			/* check member token */
			MemberToken memberToken = memberTokenRepository.findByMember(member).orElse(MemberToken.builder()
					.member(member)
					.build());
			memberToken.setRefreshToken(token.getRefreshToken());
			memberTokenRepository.save(memberToken);
			return TokenGenerateResponseDTO.builder()
					.token(token)
					.build();
		} else
			throw new TokenGenerateException("password not matches");
	}

	public TokenInvalidateResponseDTO invalidateToken(TokenInvalidateRequestDTO tokenInvalidateRequestDTO, HttpServletRequest httpServletRequest) throws Exception {
		final String memberEmail = tokenInvalidateRequestDTO.getEmail();
		final String tokenEmail = jwtHelper.getEmailFromRequest(httpServletRequest);
		if(StringUtils.equals(memberEmail, tokenEmail)) {
			Member member = memberRepository.findByEmail(memberEmail).orElseThrow(() -> new TokenInvalidateException(memberEmail+" not found."));
			memberTokenRepository.deleteByMember(member);
			return TokenInvalidateResponseDTO.builder()
					.result(true)
					.build();
		} else
			throw new TokenInvalidateException("token information is invalid.");

	}

	// jwtUtils 개선 필요
	public TokenRefreshResponseDTO refreshToken(TokenRefreshRequestDTO tokenRefreshRequestDTO) throws Exception {
		final Token requestToken = tokenRefreshRequestDTO.getToken();
		final String accessToken = requestToken.getAccessToken();
		final String refreshToken = requestToken.getRefreshToken();
		final TokenRefreshResponseDTO tokenRefreshResponseDTO = TokenRefreshResponseDTO.builder().build();

		if(jwtHelper.isTokenExpired(accessToken)) {
			String email;
			try {
				email = jwtHelper.getEmailFromToken(accessToken);
			} catch (ExpiredJwtException e) {
				email = e.getClaims().getSubject();
			}

			try {
				if(jwtHelper.isTokenExpired(refreshToken)) {
					tokenRefreshResponseDTO.setToken(Token.buildLoginRequired());
				} else {
					Member member = memberRepository.findByEmail(email).orElseThrow(NoSuchElementException::new);
					MemberToken memberToken = memberTokenRepository.findByMember(member).orElseThrow(TokenNotFoundException::new);
					final String recordRefreshToken = memberToken.getRefreshToken();
					if(StringUtils.equals(refreshToken, recordRefreshToken)) {
						Token refreshedToken = jwtHelper.generateTokenByEmail(email);
						tokenRefreshResponseDTO.setToken(Token.buildRefreshSuccess(refreshedToken.getAccessToken(), refreshedToken.getRefreshToken()));
						memberToken.setRefreshToken(refreshedToken.getRefreshToken());
						memberTokenRepository.save(memberToken);
					} else {
						tokenRefreshResponseDTO.setToken(Token.buildRefreshFail());
					}
				}
			} catch (ExpiredJwtException | TokenNotFoundException e) {
				tokenRefreshResponseDTO.setToken(Token.buildLoginRequired());
			} catch (NoSuchElementException e) {
				tokenRefreshResponseDTO.setToken(Token.buildInvalid());
			}
		} else {
			tokenRefreshResponseDTO.setToken(Token.buildAccessTokenNotExpired(accessToken, refreshToken));
		}

		return tokenRefreshResponseDTO;
	}
    
}
