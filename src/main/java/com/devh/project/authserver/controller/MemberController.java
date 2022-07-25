package com.devh.project.authserver.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.RefreshException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.service.MemberService;
import com.devh.project.authserver.dto.member.LoginRequestDTO;
import com.devh.project.authserver.dto.member.LoginResponseDTO;
import com.devh.project.authserver.dto.member.LogoutRequestDTO;
import com.devh.project.authserver.dto.member.LogoutResponseDTO;
import com.devh.project.authserver.dto.member.RefreshRequestDTO;
import com.devh.project.authserver.dto.member.RefreshResponseDTO;
import com.devh.project.authserver.dto.member.SignUpRequestDTO;
import com.devh.project.authserver.dto.member.SignUpResponseDTO;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
@Slf4j
public class MemberController {

    private final MemberService memberService;

    @Value("${aes.key}")
	private String key;

    @GetMapping("/signup")
	public ModelAndView getSignUp() {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup.html");
    	mav.addObject("aesKey", key);
    	return mav;
	}

    @PostMapping("/signup")
    public ApiResponseDTO<SignUpResponseDTO> signUp(@Valid @RequestBody SignUpRequestDTO signUpRequestDTO) throws DuplicateEmailException, PasswordException, SignUpException {
        return ApiResponseDTO.success(ApiStatus.Success.OK, memberService.signUpByMemberSignUpRequestVO(signUpRequestDTO));
    }
    
    @GetMapping("/signup/complete")
    public ModelAndView signUpComplete(@RequestParam(name = "email") String email, @RequestParam(name = "authKey") String authKey) {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup-complete.html");
    	try {
    		SignUpResponseDTO signUpResponseDTO = memberService.commitSignUpByEmailAndAuthKey(email, authKey);
			mav.addObject("message", signUpResponseDTO.getSignUpStatus().toString());
    	} catch (Exception e) {
    		log.error(e.getMessage());
			mav.addObject("message", e.getMessage());
		}
    	return mav;
    }

    @PostMapping("/login")
	public ApiResponseDTO<LoginResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequestDTO) throws LoginException {
    	log.info(loginRequestDTO.toString());
    	return ApiResponseDTO.success(ApiStatus.Success.OK, memberService.login(loginRequestDTO));
	}

	@PostMapping("/logout")
	public ApiResponseDTO<LogoutResponseDTO> logout(@Valid @RequestBody LogoutRequestDTO logoutRequestDTO, HttpServletRequest request) throws LogoutException {
    	log.info(logoutRequestDTO.toString());
		return ApiResponseDTO.success(ApiStatus.Success.OK, memberService.logout(logoutRequestDTO, request));
	}
	
	@PostMapping("/refresh")
	public ApiResponseDTO<RefreshResponseDTO> refresh(@RequestBody RefreshRequestDTO refreshRequestDTO) throws RefreshException {
		log.info(refreshRequestDTO.toString());
		return ApiResponseDTO.success(ApiStatus.Success.OK, memberService.refresh(refreshRequestDTO));
	}
}
