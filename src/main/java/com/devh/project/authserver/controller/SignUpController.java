package com.devh.project.authserver.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.devh.project.authserver.dto.member.SignUpRequestDTO;
import com.devh.project.authserver.dto.member.SignUpResponseDTO;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.service.SignUpService;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/signup")
@Slf4j
public class SignUpController {

    private final SignUpService signUpService;

    @Value("${aes.key}")
	private String key;

    @GetMapping
	public ModelAndView getSignUp() {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup.html");
    	mav.addObject("aesKey", key);
    	return mav;
	}

    @PostMapping
    public ApiResponseDTO<SignUpResponseDTO> signUp(@Valid @RequestBody SignUpRequestDTO signUpRequestDTO) throws DuplicateEmailException, PasswordException, SignUpException {
        return ApiResponseDTO.success(ApiStatus.Success.OK, signUpService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
    }
    
    @GetMapping("/complete")
    public ModelAndView signUpComplete(@RequestParam(name = "email") String email, @RequestParam(name = "authKey") String authKey) {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup-complete.html");
    	try {
    		SignUpResponseDTO signUpResponseDTO = signUpService.commitSignUpByEmailAndAuthKey(email, authKey);
			mav.addObject("message", signUpResponseDTO.getSignUpStatus().toString());
    	} catch (Exception e) {
    		log.error(e.getMessage());
			mav.addObject("message", e.getMessage());
		}
    	return mav;
    }
}
