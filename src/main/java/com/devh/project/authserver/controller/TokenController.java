package com.devh.project.authserver.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.devh.project.authserver.dto.member.LoginRequestDTO;
import com.devh.project.authserver.dto.member.LoginResponseDTO;
import com.devh.project.authserver.dto.member.LogoutRequestDTO;
import com.devh.project.authserver.dto.member.LogoutResponseDTO;
import com.devh.project.authserver.dto.member.RefreshRequestDTO;
import com.devh.project.authserver.dto.member.RefreshResponseDTO;
import com.devh.project.authserver.exception.LoginException;
import com.devh.project.authserver.exception.LogoutException;
import com.devh.project.authserver.exception.RefreshException;
import com.devh.project.authserver.service.TokenService;
import com.devh.project.common.constant.ApiStatus;
import com.devh.project.common.dto.ApiResponseDTO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/token")
@Slf4j
public class TokenController {

    private final TokenService tokenService;

    @PostMapping("/generate")
	public ApiResponseDTO<LoginResponseDTO> generate(@Valid @RequestBody LoginRequestDTO loginRequestDTO) throws LoginException {
    	log.info(loginRequestDTO.toString());
    	return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.generateToken(loginRequestDTO));
	}

	@PostMapping("/invalidate")
	public ApiResponseDTO<LogoutResponseDTO> invalidate(@Valid @RequestBody LogoutRequestDTO logoutRequestDTO, HttpServletRequest request) throws LogoutException {
    	log.info(logoutRequestDTO.toString());
		return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.invalidateToken(logoutRequestDTO, request));
	}
	
	@PostMapping("/refresh")
	public ApiResponseDTO<RefreshResponseDTO> refresh(@RequestBody RefreshRequestDTO refreshRequestDTO) throws RefreshException {
		log.info(refreshRequestDTO.toString());
		return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.refreshToken(refreshRequestDTO));
	}
}
