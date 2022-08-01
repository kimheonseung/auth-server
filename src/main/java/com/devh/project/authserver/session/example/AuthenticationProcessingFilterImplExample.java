package com.devh.project.authserver.session.example;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AuthenticationProcessingFilterImplExample extends AbstractAuthenticationProcessingFilter {

	protected AuthenticationProcessingFilterImplExample(RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		final String email = request.getParameter("email");
		final String credentials = request.getParameter("password");
		return getAuthenticationManager().authenticate(new AuthenticationTokenImplExample(email, credentials, null));
	}

}
