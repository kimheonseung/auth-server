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
import com.devh.project.authserver.vo.member.LoginRequestVO;
import com.devh.project.authserver.vo.member.LoginResponseVO;
import com.devh.project.authserver.vo.member.LogoutRequestVO;
import com.devh.project.authserver.vo.member.LogoutResponseVO;
import com.devh.project.authserver.vo.member.RefreshRequestVO;
import com.devh.project.authserver.vo.member.RefreshResponseVO;
import com.devh.project.authserver.vo.member.SignUpRequestVO;
import com.devh.project.authserver.vo.member.SignUpResponseVO;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.vo.ApiResponseVO;

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
    public ApiResponseVO<SignUpResponseVO> signUp(@Valid @RequestBody SignUpRequestVO signUpRequestVO) throws DuplicateEmailException, PasswordException, SignUpException {
        return ApiResponseVO.success(ApiStatus.Success.OK, memberService.signUpByMemberSignUpRequestVO(signUpRequestVO));
    }
    
    @GetMapping("/signup/complete")
    public ModelAndView signUpComplete(@RequestParam(name = "email") String email, @RequestParam(name = "authKey") String authKey) {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup-complete.html");
    	try {
    		SignUpResponseVO signUpResponseVO = memberService.commitSignUpByEmailAndAuthKey(email, authKey);
			mav.addObject("message", signUpResponseVO.getSignUpStatus().toString());
    	} catch (Exception e) {
    		log.error(e.getMessage());
			mav.addObject("message", e.getMessage());
		}
    	return mav;
    }

    @PostMapping("/login")
	public ApiResponseVO<LoginResponseVO> login(@Valid @RequestBody LoginRequestVO loginRequestVO) throws LoginException {
    	log.info(loginRequestVO.toString());
    	return ApiResponseVO.success(ApiStatus.Success.OK, memberService.login(loginRequestVO));
	}

	@PostMapping("/logout")
	public ApiResponseVO<LogoutResponseVO> logout(@Valid @RequestBody LogoutRequestVO logoutRequestVO, HttpServletRequest request) throws LogoutException {
    	log.info(logoutRequestVO.toString());
		return ApiResponseVO.success(ApiStatus.Success.OK, memberService.logout(logoutRequestVO, request));
	}
	
	@PostMapping("/refresh")
	public ApiResponseVO<RefreshResponseVO> refresh(@RequestBody RefreshRequestVO refreshRequestVO) throws RefreshException {
		log.info(refreshRequestVO.toString());
		return ApiResponseVO.success(ApiStatus.Success.OK, memberService.refresh(refreshRequestVO));
	}
}
