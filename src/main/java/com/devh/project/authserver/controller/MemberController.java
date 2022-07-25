package com.devh.project.authserver.controller;

import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.exception.RefreshException;
import com.devh.project.authserver.exception.SignUpException;
import com.devh.project.authserver.service.MemberService;
import com.devh.project.authserver.vo.MemberLoginRequestVO;
import com.devh.project.authserver.vo.MemberLoginResponseVO;
import com.devh.project.authserver.vo.MemberLogoutRequestVO;
import com.devh.project.authserver.vo.MemberLogoutResponseVO;
import com.devh.project.authserver.vo.MemberRefreshRequestVO;
import com.devh.project.authserver.vo.MemberRefreshResponseVO;
import com.devh.project.authserver.vo.MemberSignUpRequestVO;
import com.devh.project.authserver.vo.MemberSignUpResponseVO;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.vo.ApiResponseVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

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
    public ApiResponseVO<MemberSignUpResponseVO> signUp(@Valid @RequestBody MemberSignUpRequestVO memberSignUpRequestVO) throws DuplicateEmailException, PasswordException, SignUpException {
        return ApiResponseVO.success(ApiStatus.Success.OK, memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO));
    }
    
    @GetMapping("/signup/complete")
    public ModelAndView signUpComplete(@RequestParam(name = "email") String email, @RequestParam(name = "authKey") String authKey) {
    	ModelAndView mav = new ModelAndView();
    	mav.setViewName("/member/signup-complete.html");
    	try {
    		MemberSignUpResponseVO memberSignUpResponseVO = memberService.commitSignUpByEmailAndAuthKey(email, authKey);
			mav.addObject("message", memberSignUpResponseVO.getSignUpStatus().toString());
    	} catch (Exception e) {
    		log.error(e.getMessage());
			mav.addObject("message", e.getMessage());
		}
    	return mav;
    }

    @PostMapping("/login")
	public ApiResponseVO<MemberLoginResponseVO> login(@Valid @RequestBody MemberLoginRequestVO memberLoginRequestVO) throws LoginException {
    	log.info(memberLoginRequestVO.toString());
    	return ApiResponseVO.success(ApiStatus.Success.OK, memberService.login(memberLoginRequestVO));
	}

	@PostMapping("/logout")
	public ApiResponseVO<MemberLogoutResponseVO> logout(@Valid @RequestBody MemberLogoutRequestVO memberLogoutRequestVO, HttpServletRequest request) throws LogoutException {
    	log.info(memberLogoutRequestVO.toString());
		return ApiResponseVO.success(ApiStatus.Success.OK, memberService.logout(memberLogoutRequestVO, request));
	}
	
	@PostMapping("/refresh")
	public ApiResponseVO<MemberRefreshResponseVO> refresh(@RequestBody MemberRefreshRequestVO memberRefreshRequestVO) throws RefreshException {
		log.info(memberRefreshRequestVO.toString());
		return ApiResponseVO.success(ApiStatus.Success.OK, memberService.refresh(memberRefreshRequestVO));
	}
}
