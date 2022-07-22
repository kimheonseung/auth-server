package com.devh.project.authserver.controller;

import javax.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.devh.project.authserver.constant.SignUpStatus;
import com.devh.project.authserver.exception.DuplicateEmailException;
import com.devh.project.authserver.exception.PasswordException;
import com.devh.project.authserver.service.MemberService;
import com.devh.project.authserver.vo.MemberSignUpRequestVO;
import com.devh.project.authserver.vo.MemberSignUpResponseVO;
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

    @PostMapping("/signup")
    public ApiResponseVO<MemberSignUpResponseVO> signUp(@Valid @RequestBody MemberSignUpRequestVO memberSignUpRequestVO) throws DuplicateEmailException, PasswordException {
        return ApiResponseVO.success(ApiStatus.Success.OK, memberService.signUpByMemberSignUpRequestVO(memberSignUpRequestVO));
    }
    
    @GetMapping("/signup/complete")
    public ModelAndView signUpComplete(@RequestParam(name = "email") String email, @RequestParam(name = "authKey") String authKey) {
    	ModelAndView mav = new ModelAndView();
    	
    	try {
    		MemberSignUpResponseVO memberSignUpResponseVO = memberService.commitSignUpByEmailAndAuthKey(email, authKey);
    		if(SignUpStatus.COMPLETED.equals(memberSignUpResponseVO.getSignUpStatus()))
    			mav.setViewName("/signup-success.html");
    		else
    			mav.setViewName("/signup-error.html");
    	} catch (Exception e) {
    		log.error(e.getMessage());
    		mav.setViewName("/signup-error.html");
		}
    	
    	return mav;
    }
}
