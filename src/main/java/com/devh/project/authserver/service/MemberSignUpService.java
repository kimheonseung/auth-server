package com.devh.project.authserver.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.dto.member.SignUpRequestDTO;
import com.devh.project.authserver.dto.member.SignUpResponseDTO;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.AuthKeyHelper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class MemberSignUpService {

    private final AES256Helper aes256Helper;
    private final MemberRepository memberRepository;
    private final RedisMemberRepository redisMemberRepository;
    private final AuthKeyHelper authKeyHelper;
    private final BCryptHelper bcryptHelper;
    private final MailService mailService;

    public SignUpResponseDTO signUpByMemberSignUpRequestVO(SignUpRequestDTO signUpRequestDTO) throws DuplicateEmailException, PasswordException {
    	try {
    		final String email = signUpRequestDTO.getEmail();
    		/* exist check */
    		if(memberRepository.existsByEmail(email))
    			throw new DuplicateEmailException(email+" already exists.");
    		/* save temporary until email authentication */
    		RedisMember redisMember = redisMemberRepository.save(toRedisMember(signUpRequestDTO));
    		/* send mail */
    		mailService.sendSignupValidationMail(signUpRequestDTO.getEmail(), redisMember.getAuthKey());
    		/* return sign up response */
    		return SignUpResponseDTO.builder()
    				.signUpStatus(email.equals(redisMember.getEmail()) ? SignUpStatus.REQUESTED : SignUpStatus.ERROR)
    				.email(email)
    				.build();
    	} catch (DuplicateEmailException | PasswordException e) {
			throw e;
		} catch (Exception e) {
			throw new SignUpException(e.getMessage());
		}
    }
    
    public SignUpResponseDTO commitSignUpByEmailAndAuthKey(String email, String authKey) throws SignUpException {
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
        	return SignUpResponseDTO.builder()
                	.signUpStatus(email.equals(member.getEmail()) ? SignUpStatus.COMPLETED : SignUpStatus.ERROR)
                	.email(email)
                	.build();
    	} catch (Exception e) {
    		log.error(e.getMessage());
    		throw new SignUpException(e.getMessage());
		}
    }


    private Member toMember(RedisMember redisMember) {
        return Member.builder()
                .email(redisMember.getEmail())
                .name(redisMember.getName())
                .password(redisMember.getPassword())
                .build();
    }
    
    private RedisMember toRedisMember(SignUpRequestDTO memberSignUpRequestDTO) throws PasswordException {
    	try {
    		return RedisMember.builder()
    				.email(memberSignUpRequestDTO.getEmail())
    				.name(memberSignUpRequestDTO.getName())
    				.password(bcryptHelper.encode(aes256Helper.decrypt(memberSignUpRequestDTO.getPassword())))
//					.password(passwordEncoder.encode(memberSignUpRequestVO.getPassword()))
    				.authKey(authKeyHelper.generateAuthKey())
    				.build();
    	} catch (Exception e) {
			throw new PasswordException("Something wrong with your password. "+e.getMessage());
		}
    }
    
}
