package com.devh.project.authserver.token.service;

import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.exception.TokenGenerateException;
import com.devh.project.authserver.exception.TokenInvalidateException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.TokenRefreshException;
import com.devh.project.authserver.exception.TokenNotFoundException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.helper.JwtHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.token.Token;
import com.devh.project.authserver.token.TokenStatus;
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

    public TokenGenerateResponseDTO generateToken(TokenGenerateRequestDTO tokenGenerateRequestDTO) throws TokenGenerateException {

    	try {
    		final String email = tokenGenerateRequestDTO.getEmail();
    		String password = tokenGenerateRequestDTO.getPassword();
			Token tokenDTO;
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
			return TokenGenerateResponseDTO.builder()
					.token(tokenDTO)
					.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new TokenGenerateException(e.getMessage());
		}
	}

	public TokenInvalidateResponseDTO invalidateToken(TokenInvalidateRequestDTO tokenInvalidateRequestDTO, HttpServletRequest httpServletRequest) throws TokenInvalidateException {
    	try {
    		final String memberEmail = tokenInvalidateRequestDTO.getEmail();
    		final String tokenEmail = jwtHelper.getEmailFromRequest(httpServletRequest);
    		boolean result = false;
    		if(memberEmail.equals(tokenEmail)) {
    			Member member = memberRepository.findByEmail(memberEmail).orElseThrow(() -> new NoSuchElementException(memberEmail+" not found."));
    			memberTokenRepository.deleteByMember(member);
    			result = true;
			}

    		return TokenInvalidateResponseDTO.builder()
    				.result(result)
    				.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new TokenInvalidateException(e.getMessage());
		}
	}
	
	public TokenRefreshResponseDTO refreshToken(TokenRefreshRequestDTO tokenRefreshRequestDTO) throws TokenRefreshException {
		try {
			final Token requestToken = tokenRefreshRequestDTO.getToken();
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
                            Token refreshTokenDTO = jwtHelper.generateTokenByEmail(email);
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
			
			return TokenRefreshResponseDTO.builder()
					.token(requestToken)
					.build();
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new TokenRefreshException(e.getMessage());
		}
	}
    
}
