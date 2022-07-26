package com.devh.project.authserver.token.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.devh.project.authserver.token.exception.TokenGenerateException;
import com.devh.project.authserver.token.exception.TokenInvalidateException;
import com.devh.project.authserver.token.exception.TokenRefreshException;
import com.devh.project.authserver.token.dto.TokenGenerateRequestDTO;
import com.devh.project.authserver.token.dto.TokenGenerateResponseDTO;
import com.devh.project.authserver.token.dto.TokenInvalidateRequestDTO;
import com.devh.project.authserver.token.dto.TokenInvalidateResponseDTO;
import com.devh.project.authserver.token.dto.TokenRefreshRequestDTO;
import com.devh.project.authserver.token.dto.TokenRefreshResponseDTO;
import com.devh.project.authserver.token.service.TokenService;
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
	public ApiResponseDTO<TokenGenerateResponseDTO> generate(@Valid @RequestBody TokenGenerateRequestDTO loginRequestDTO) throws Exception {
    	return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.generateToken(loginRequestDTO));
	}

	@PostMapping("/invalidate")
	public ApiResponseDTO<TokenInvalidateResponseDTO> invalidate(@Valid @RequestBody TokenInvalidateRequestDTO logoutRequestDTO, HttpServletRequest request) throws Exception {
		return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.invalidateToken(logoutRequestDTO, request));
	}
	
	@PostMapping("/refresh")
	public ApiResponseDTO<TokenRefreshResponseDTO> refresh(@RequestBody TokenRefreshRequestDTO refreshRequestDTO) throws Exception {
		return ApiResponseDTO.success(ApiStatus.Success.OK, tokenService.refreshToken(refreshRequestDTO));
	}
}
