package com.devh.project.authserver.service;

import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.constant.TokenStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.RefreshException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.exception.TokenNotFoundException;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.util.AES256Utils;
import com.devh.project.authserver.util.AuthKeyUtils;
import com.devh.project.authserver.util.BCryptUtils;
import com.devh.project.authserver.util.JwtUtils;
import com.devh.project.authserver.vo.TokenVO;
import com.devh.project.authserver.vo.member.LoginRequestVO;
import com.devh.project.authserver.vo.member.LoginResponseVO;
import com.devh.project.authserver.vo.member.LogoutRequestVO;
import com.devh.project.authserver.vo.member.LogoutResponseVO;
import com.devh.project.authserver.vo.member.RefreshRequestVO;
import com.devh.project.authserver.vo.member.RefreshResponseVO;
import com.devh.project.authserver.vo.member.SignUpRequestVO;
import com.devh.project.authserver.vo.member.SignUpResponseVO;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final AES256Utils aes256Utils;
    private final MemberRepository memberRepository;
    private final MemberTokenRepository memberTokenRepository;
    private final RedisMemberRepository redisMemberRepository;
    private final AuthKeyUtils authKeyUtils;
    private final JwtUtils jwtUtils;
    private final BCryptUtils bcryptUtils;
    private final MailService mailService;

    public SignUpResponseVO signUpByMemberSignUpRequestVO(SignUpRequestVO signUpRequestVO) throws DuplicateEmailException, PasswordException {
    	try {
    		final String email = signUpRequestVO.getEmail();
    		/* exist check */
    		if(memberRepository.existsByEmail(email))
    			throw new DuplicateEmailException(email+" already exists.");
    		/* save temporary until email authentication */
    		RedisMember redisMember = redisMemberRepository.save(toRedisMember(signUpRequestVO));
    		/* send mail */
    		mailService.sendSignupValidationMail(signUpRequestVO.getEmail(), redisMember.getAuthKey());
    		/* return sign up response */
    		return SignUpResponseVO.builder()
    				.signUpStatus(email.equals(redisMember.getEmail()) ? SignUpStatus.REQUESTED : SignUpStatus.ERROR)
    				.email(email)
    				.build();
    	} catch (DuplicateEmailException | PasswordException e) {
			throw e;
		} catch (Exception e) {
			throw new SignUpException(e.getMessage());
		}
    }
    
    public SignUpResponseVO commitSignUpByEmailAndAuthKey(String email, String authKey) throws SignUpException {
    	try {
    		/* redis check */
        	RedisMember redisMember = redisMemberRepository.findById(email).orElse(null);
        	if(redisMember == null)
        		throw new SignUpException("Failed to sign up ["+email+"]. Maybe time expired.");
        	/* auth key check */
        	if(!authKey.equals(redisMember.getAuthKey())) 
        		throw new SignUpException("Invalid Authentication URL.");
        	/* db check */
        	if(memberRepository.existsByEmail(email))
        		throw new SignUpException("Already exists.");
        	/* save */
        	Member member = memberRepository.save(toMember(redisMember));
        	redisMemberRepository.deleteById(email);
        	return SignUpResponseVO.builder()
                	.signUpStatus(email.equals(member.getEmail()) ? SignUpStatus.COMPLETED : SignUpStatus.ERROR)
                	.email(email)
                	.build();
    	} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new SignUpException(e.getMessage());
		}
    }

    public LoginResponseVO login(LoginRequestVO loginRequestVO) throws LoginException {

    	try {
    		final String email = loginRequestVO.getEmail();
    		String password = loginRequestVO.getPassword();
			TokenVO tokenVO;
			password = aes256Utils.decrypt(password);
			/* member check */
			Member member = memberRepository.findByEmail(email).orElseThrow(() -> new NoSuchElementException(email + " does not exists."));
			if(bcryptUtils.matches(password, member.getPassword())) {
				/* generate token */
				tokenVO = jwtUtils.generateTokenByEmail(email);
			} else {
				throw new PasswordException("password not matches");
			}

			/* check member token */
			MemberToken memberToken = memberTokenRepository.findByMember(member).orElse(MemberToken.builder()
					.member(member)
					.build());
			memberToken.setRefreshToken(tokenVO.getRefreshToken());
			memberTokenRepository.save(memberToken);
			return LoginResponseVO.builder()
					.token(tokenVO)
					.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LoginException(e.getMessage());
		}
	}

	public LogoutResponseVO logout(LogoutRequestVO logoutRequestVO, HttpServletRequest httpServletRequest) throws LogoutException {
    	try {
    		final String memberEmail = logoutRequestVO.getEmail();
    		final String tokenEmail = jwtUtils.getEmailFromRequest(httpServletRequest);
    		boolean result = false;
    		if(memberEmail.equals(tokenEmail)) {
    			Member member = memberRepository.findByEmail(memberEmail).orElseThrow(() -> new NoSuchElementException(memberEmail+" not found."));
    			memberTokenRepository.deleteByMember(member);
    			result = true;
			}

    		return LogoutResponseVO.builder()
    				.result(result)
    				.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LogoutException(e.getMessage());
		}
	}
	
	public RefreshResponseVO refresh(RefreshRequestVO refreshRequestVO) throws RefreshException {
		try {
			final TokenVO requestToken = refreshRequestVO.getToken();
			final String accessToken = requestToken.getAccessToken();
			final String refreshToken = requestToken.getRefreshToken();
			
			boolean isAccessTokenExpired = false;
			String email = null;
			
			try {
                isAccessTokenExpired = jwtUtils.isTokenExpired(accessToken);
                if(isAccessTokenExpired) {
                	email = jwtUtils.getEmailFromToken(accessToken);
                } else {
                	requestToken.setTokenStatus(TokenStatus.ACCESS_TOKEN_NOT_EXPIRED);
                }
            } catch (ExpiredJwtException e) {
                email = e.getClaims().getSubject();
                isAccessTokenExpired = true;
            }
			
			if(isAccessTokenExpired) {
                try {
                    if(!jwtUtils.isTokenExpired(refreshToken)) {
                        Member member = memberRepository.findByEmail(email).orElseThrow(NoSuchElementException::new);
                        MemberToken memberToken = memberTokenRepository.findByMember(member).orElseThrow(TokenNotFoundException::new);
                        final String recordRefreshToken = memberToken.getRefreshToken();
                        if(refreshToken.equals(recordRefreshToken)) {
                            TokenVO refreshTokenVO = jwtUtils.generateTokenByEmail(email);
                            requestToken.setTokenStatus(TokenStatus.REFRESH_SUCCESS);
                            requestToken.setAccessToken(refreshTokenVO.getAccessToken());
                            requestToken.setRefreshToken(refreshTokenVO.getRefreshToken());
                            memberToken.setRefreshToken(refreshTokenVO.getRefreshToken());
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
			
			return RefreshResponseVO.builder()
					.token(requestToken)
					.build();
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new RefreshException(e.getMessage());
		}
	}

    private Member toMember(RedisMember redisMember) {
        return Member.builder()
                .email(redisMember.getEmail())
                .name(redisMember.getName())
                .password(redisMember.getPassword())
                .build();
    }
    
    private RedisMember toRedisMember(SignUpRequestVO memberSignUpRequestVO) throws PasswordException {
    	try {
    		return RedisMember.builder()
    				.email(memberSignUpRequestVO.getEmail())
    				.name(memberSignUpRequestVO.getName())
    				.password(bcryptUtils.encode(aes256Utils.decrypt(memberSignUpRequestVO.getPassword())))
//					.password(passwordEncoder.encode(memberSignUpRequestVO.getPassword()))
    				.authKey(authKeyUtils.generateAuthKey())
    				.build();
    	} catch (Exception e) {
			throw new PasswordException("Something wrong with your password. "+e.getMessage());
		}
    }
    
}
