package com.devh.project.authserver.signup.service;

import com.devh.project.authserver.domain.Member;
import com.devh.project.authserver.domain.RedisMember;
import com.devh.project.authserver.signup.exception.DuplicateEmailException;
import com.devh.project.authserver.signup.exception.PasswordException;
import com.devh.project.authserver.signup.exception.SignUpException;
import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.authserver.helper.AuthKeyHelper;
import com.devh.project.authserver.helper.BCryptHelper;
import com.devh.project.authserver.helper.MailHelper;
import com.devh.project.authserver.repository.MemberRepository;
import com.devh.project.authserver.repository.RedisMemberRepository;
import com.devh.project.authserver.signup.SignUpStatus;
import com.devh.project.authserver.signup.dto.SignUpRequestDTO;
import com.devh.project.authserver.signup.dto.SignUpResponseDTO;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class SignUpService {

    private final AES256Helper aes256Helper;
    private final MemberRepository memberRepository;
    private final RedisMemberRepository redisMemberRepository;
    private final AuthKeyHelper authKeyHelper;
    private final BCryptHelper bcryptHelper;
    private final MailHelper mailService;

    public SignUpResponseDTO signUpByMemberSignUpRequestVO(SignUpRequestDTO signUpRequestDTO) {
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
    			.signUpStatus(StringUtils.equals(email, redisMember.getEmail()) ? SignUpStatus.REQUESTED : SignUpStatus.ERROR)
    			.email(email)
    			.build();
    }
    
    public SignUpResponseDTO commitSignUpByEmailAndAuthKey(String email, String authKey) {
		/* redis check */
		RedisMember redisMember = redisMemberRepository.findById(email).orElse(null);
		if(redisMember == null)
			throw new SignUpException("Failed to sign up ["+email+"]. Maybe time expired.");
		/* auth key check */
		if(!StringUtils.equals(authKey, redisMember.getAuthKey()))
			throw new SignUpException("Invalid Authentication URL.");
		/* db check */
		if(memberRepository.existsByEmail(email))
			throw new SignUpException("Already exists.");
		/* save */
		Member member = memberRepository.save(toMember(redisMember));
		redisMemberRepository.deleteById(email);
		return SignUpResponseDTO.builder()
				.signUpStatus(StringUtils.equals(email, member.getEmail()) ? SignUpStatus.COMPLETED : SignUpStatus.ERROR)
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
    
    private RedisMember toRedisMember(SignUpRequestDTO memberSignUpRequestDTO) throws PasswordException {
    	try {
    		return RedisMember.builder()
    				.email(memberSignUpRequestDTO.getEmail())
    				.name(memberSignUpRequestDTO.getName())
    				.password(bcryptHelper.encode(aes256Helper.decrypt(memberSignUpRequestDTO.getPassword())))
    				.authKey(authKeyHelper.generateAuthKey())
    				.build();
    	} catch (Exception e) {
			throw new PasswordException("Something wrong with your password. "+e.getMessage());
		}
    }
    
}
