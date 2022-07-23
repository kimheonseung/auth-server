package com.devh.project.authserver.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.util.AES256Utils;
import com.devh.project.authserver.util.AuthKeyUtils;
import com.devh.project.authserver.vo.MemberSignUpRequestVO;
import com.devh.project.authserver.vo.MemberSignUpResponseVO;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final AES256Utils aes256Utils;
    private final MemberRepository memberRepository;
    private final RedisMemberRepository redisMemberRepository;
    private final AuthKeyUtils authKeyUtils;
    private final MailService mailService;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

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
//    				.password(passwordEncoder.encode(aes256Utils.decrypt(memberSignUpRequestVO.getPassword())))
					.password(passwordEncoder.encode(memberSignUpRequestVO.getPassword()))
    				.authKey(authKeyUtils.generateAuthKey())
    				.build();
    	} catch (Exception e) {
			throw new PasswordException("Something wrong with your password.");
		}
    }
    
}
