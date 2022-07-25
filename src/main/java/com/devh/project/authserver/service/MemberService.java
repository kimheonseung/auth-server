package com.devh.project.authserver.service;

import java.util.NoSuchElementException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.MemberToken;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.MemberTokenRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.util.AES256Utils;
import com.devh.project.authserver.util.AuthKeyUtils;
import com.devh.project.authserver.util.BCryptUtils;
import com.devh.project.authserver.util.JwtUtils;
import com.devh.project.authserver.vo.MemberLoginRequestVO;
import com.devh.project.authserver.vo.MemberLoginResponseVO;
import com.devh.project.authserver.vo.MemberLogoutRequestVO;
import com.devh.project.authserver.vo.MemberLogoutResponseVO;
import com.devh.project.authserver.vo.MemberSignUpRequestVO;
import com.devh.project.authserver.vo.MemberSignUpResponseVO;
import com.devh.project.authserver.vo.TokenVO;

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

    public MemberSignUpResponseVO signUpByMemberSignUpRequestVO(MemberSignUpRequestVO memberSignUpRequestVO) throws DuplicateEmailException, PasswordException {
        final String email = memberSignUpRequestVO.getEmail();
        /* exist check */
        if(memberRepository.existsByEmail(email))
            throw new DuplicateEmailException(email+" already exists.");
        /* save temporary until email authentication */
        RedisMember redisMember = redisMemberRepository.save(toRedisMember(memberSignUpRequestVO));
        /* send mail */
		mailService.sendSignupValidationMail(memberSignUpRequestVO.getEmail(), redisMember.getAuthKey());
        /* return sign up response */
        return MemberSignUpResponseVO.builder()
            	.signUpStatus(email.equals(redisMember.getEmail()) ? SignUpStatus.REQUESTED : SignUpStatus.ERROR)
            	.email(email)
            	.build();
    }
    
    public MemberSignUpResponseVO commitSignUpByEmailAndAuthKey(String email, String authKey) {
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
    	return MemberSignUpResponseVO.builder()
            	.signUpStatus(email.equals(member.getEmail()) ? SignUpStatus.COMPLETED : SignUpStatus.ERROR)
            	.email(email)
            	.build();
    }

    public MemberLoginResponseVO login(MemberLoginRequestVO memberLoginRequestVO) throws LoginException {
    	final String email = memberLoginRequestVO.getEmail();
    	String password = memberLoginRequestVO.getPassword();

    	try {
			TokenVO tokenVO;
			password = aes256Utils.decrypt(password);
			Member member = memberRepository.findByEmail(email).orElseThrow(() -> new NoSuchElementException(email + " does not exists."));
			if(bcryptUtils.matches(password, member.getPassword())) {
				tokenVO = jwtUtils.generateTokenByEmail(email);
			} else {
				throw new PasswordException("password not matches");
			}

			MemberToken memberToken = memberTokenRepository.findByMember(member).orElse(MemberToken.builder()
					.member(member)
					.build());
			memberToken.setRefreshToken(tokenVO.getRefreshToken());

			memberTokenRepository.save(memberToken);
			return MemberLoginResponseVO.builder()
					.token(tokenVO)
					.build();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LoginException(e.getMessage());
		}
	}

	public MemberLogoutResponseVO logout(MemberLogoutRequestVO memberLogoutRequestVO, HttpServletRequest httpServletRequest) {
    	final String memberEmail = memberLogoutRequestVO.getEmail();
    	final String tokenEmail = jwtUtils.getEmailFromRequest(httpServletRequest);
    	try {
    		if(memberEmail.equals(tokenEmail)) {
    			Member member = memberRepository.findByEmail(memberEmail).orElseThrow(() -> new NoSuchElementException(memberEmail+" not found."));
    			memberTokenRepository.deleteByMember(member);
			}

    		return new MemberLogoutResponseVO();
		} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new LogoutException(e.getMessage());
		}
	}

    private Member toMember(RedisMember redisMember) {
        return Member.builder()
                .email(redisMember.getEmail())
                .name(redisMember.getName())
                .password(redisMember.getPassword())
                .build();
    }
    
    private RedisMember toRedisMember(MemberSignUpRequestVO memberSignUpRequestVO) throws PasswordException {
    	try {
    		return RedisMember.builder()
    				.email(memberSignUpRequestVO.getEmail())
    				.name(memberSignUpRequestVO.getName())
    				.password(bcryptUtils.encode(aes256Utils.decrypt(memberSignUpRequestVO.getPassword())))
//					.password(passwordEncoder.encode(memberSignUpRequestVO.getPassword()))
    				.authKey(authKeyUtils.generateAuthKey())
    				.build();
    	} catch (Exception e) {
			throw new PasswordException("Something wrong with your password.");
		}
    }
    
}
