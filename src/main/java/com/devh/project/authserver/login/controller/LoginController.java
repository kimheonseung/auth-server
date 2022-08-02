package com.devh.project.authserver.login.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/login")
public class LoginController {
	
	@Value("${aes.key}")
	private String key;
	
	@GetMapping
	public ModelAndView getLogin() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("login.html");
		mav.addObject("aesKey", key);
		return mav;
	}
	@GetMapping("/complete")
	public ModelAndView getLoginComplete() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("login-complete.html");
		return mav;
	}
	@GetMapping("/fail")
	public ModelAndView getLoginFail() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("login-fail.html");
		return mav;
	}
	
//	@PostMapping
//	public 
}
