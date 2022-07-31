package com.devh.project.authserver.configuration;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.devh.project.common.constant.ApiStatus.AuthError;
import com.devh.project.common.dto.ApiResponseDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	// https://dev-coco.tistory.com/174
    // https://www.inflearn.com/questions/34886
    // https://mangkyu.tistory.com/77
	
	private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
	
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // configuring HttpSecurity
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**")
                .authorizeRequests()
                	.antMatchers("/logout", "/refresh").hasAuthority("USER")
                .and()
                .httpBasic().disable()
                .formLogin().disable()
                .cors().disable()
                .csrf().disable()
                .exceptionHandling()
                	.accessDeniedHandler(accessDeniedHandler())
                	.authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .sessionManagement()
                	.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                	.maximumSessions(5)
                	.maxSessionsPreventsLogin(true);
                
        return http.build();
    }

    // configuring WebSecurity
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().mvcMatchers("/signup", "/login");
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(ApiResponseDTO.authError(AuthError.ACCESS_DENIED)));
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, e) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(ApiResponseDTO.authError(AuthError.UNAUTHORIZED)));
            response.getWriter().flush();
            response.getWriter().close();
        };
    }
}
