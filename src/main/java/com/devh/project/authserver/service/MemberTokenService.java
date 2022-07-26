package com.devh.project.authserver.service;

import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.TokenStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.dto.TokenDTO;
import com.devh.project.authserver.dto.member.LoginRequestDTO;
import com.devh.project.authserver.dto.member.LoginResponseDTO;
import com.devh.project.authserver.dto.member.LogoutRequestDTO;
import com.devh.project.authserver.dto.member.LogoutResponseDTO;
import com.devh.project.authserver.dto.member.RefreshRequestDTO;
import com.devh.project.authserver.dto.member.RefreshResponseDTO;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.RefreshException;
import com.devh.project.authserver.exception.TokenNotFoundException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.helper.JwtHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class MemberTokenService {

    private final AES256Helper aes256Helper;
    private final MemberRepository memberRepository;
    private final MemberTokenRepository memberTokenRepository;
    private final JwtHelper jwtHelper;
    private final BCryptHelper bcryptHelper;

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) throws LoginException {

    	try {
    		final String email = loginRequestDTO.getEmail();
    		String password = loginRequestDTO.getPassword();
			TokenDTO tokenDTO;
			password = aes256Helper.decrypt(password);
			/* member check */
			Member member = memberRepository.findByEmail(email).orElseThrow(() -> new NoSuchElementException(email + " does not exists."));
			if(bcryptHelper.matches(password, member.getPassword())) {
				/* generate token */
				tokenDTO = jwtHelper.generateTokenByEmail(email);
			} else {
				throw new PasswordException("password not matches");
			}

			/* check member token */
			MemberToken memberToken = memberTokenRepository.findByMember(member).orElse(MemberToken.builder()
					.member(member)
					.build());
			memberToken.setRefreshToken(tokenDTO.getRefreshToken());
			memberTokenRepository.save(memberToken);
			return LoginResponseDTO.builder()
					.token(tokenDTO)
					.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LoginException(e.getMessage());
		}
	}

	public LogoutResponseDTO logout(LogoutRequestDTO logoutRequestDTO, HttpServletRequest httpServletRequest) throws LogoutException {
    	try {
    		final String memberEmail = logoutRequestDTO.getEmail();
    		final String tokenEmail = jwtHelper.getEmailFromRequest(httpServletRequest);
    		boolean result = false;
    		if(memberEmail.equals(tokenEmail)) {
    			Member member = memberRepository.findByEmail(memberEmail).orElseThrow(() -> new NoSuchElementException(memberEmail+" not found."));
    			memberTokenRepository.deleteByMember(member);
    			result = true;
			}

    		return LogoutResponseDTO.builder()
    				.result(result)
    				.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LogoutException(e.getMessage());
		}
	}
	
	public RefreshResponseDTO refresh(RefreshRequestDTO refreshRequestDTO) throws RefreshException {
		try {
			final TokenDTO requestToken = refreshRequestDTO.getToken();
			final String accessToken = requestToken.getAccessToken();
			final String refreshToken = requestToken.getRefreshToken();
			
			boolean isAccessTokenExpired = false;
			String email = null;
			
			try {
                isAccessTokenExpired = jwtHelper.isTokenExpired(accessToken);
                if(isAccessTokenExpired) {
                	email = jwtHelper.getEmailFromToken(accessToken);
                } else {
                	requestToken.setTokenStatus(TokenStatus.ACCESS_TOKEN_NOT_EXPIRED);
                }
            } catch (ExpiredJwtException e) {
                email = e.getClaims().getSubject();
                isAccessTokenExpired = true;
            }
			
			if(isAccessTokenExpired) {
                try {
                    if(!jwtHelper.isTokenExpired(refreshToken)) {
                        Member member = memberRepository.findByEmail(email).orElseThrow(NoSuchElementException::new);
                        MemberToken memberToken = memberTokenRepository.findByMember(member).orElseThrow(TokenNotFoundException::new);
                        final String recordRefreshToken = memberToken.getRefreshToken();
                        if(refreshToken.equals(recordRefreshToken)) {
                            TokenDTO refreshTokenDTO = jwtHelper.generateTokenByEmail(email);
                            requestToken.setTokenStatus(TokenStatus.REFRESH_SUCCESS);
                            requestToken.setAccessToken(refreshTokenDTO.getAccessToken());
                            requestToken.setRefreshToken(refreshTokenDTO.getRefreshToken());
                            memberToken.setRefreshToken(refreshTokenDTO.getRefreshToken());
                            memberTokenRepository.save(memberToken);
                        } else {
                        	requestToken.setTokenStatus(TokenStatus.REFRESH_FAIL);
                        	requestToken.setAccessToken(null);
                        	requestToken.setRefreshToken(null);
                        }
                    } else {
                    	requestToken.setTokenStatus(TokenStatus.LOGIN_REQUIRED);
                    	requestToken.setAccessToken(null);
                    	requestToken.setRefreshToken(null);
                    }
                } catch (ExpiredJwtException | TokenNotFoundException e) {
                	requestToken.setTokenStatus(TokenStatus.LOGIN_REQUIRED);
                	requestToken.setAccessToken(null);
                	requestToken.setRefreshToken(null);
                } catch (NoSuchElementException e) {
					requestToken.setTokenStatus(TokenStatus.INVALID);
					requestToken.setAccessToken(null);
                	requestToken.setRefreshToken(null);
				}
            }
			
			return RefreshResponseDTO.builder()
					.token(requestToken)
					.build();
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new RefreshException(e.getMessage());
		}
	}
    
}
