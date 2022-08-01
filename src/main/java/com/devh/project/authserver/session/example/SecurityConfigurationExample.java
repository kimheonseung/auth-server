package com.devh.project.authserver.session.example;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.devh.project.authserver.helper.AES256Helper;
import com.devh.project.common.constant.ApiStatus.AuthError;
import com.devh.project.common.dto.ApiResponseDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

//@Configuration
//@EnableWebSecurity
public class SecurityConfigurationExample {

	// https://dev-coco.tistory.com/174
    // https://www.inflearn.com/questions/34886
    // https://mangkyu.tistory.com/77
	
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private AES256Helper aes256Helper;
	
	private static final String[] RESOURCES = {
			"classpath:/static/**",
	}; 
	
	private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
	
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    	return authenticationConfiguration.getAuthenticationManager();
    	
    }
    
    // AuthenticationProvider
    public AuthenticationProvider authenticationProvider() {
    	return new AuthenticationProviderImplExample(userDetailsService, passwordEncoder(), aes256Helper);
    }
    
    // configuring HttpSecurity
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
        		.csrf().disable()
        		.httpBasic().disable()
                .cors().disable()
        		.formLogin()
        			.loginPage("/login/form")
        			.loginProcessingUrl("/login/process")
        			.usernameParameter("email")
        			.passwordParameter("passowrd")
        			.successForwardUrl("/login/complete")
        			.failureForwardUrl("/login/fail")
        			// 위 3개의 경우 모두 허용
        			.permitAll()
        			.and()
        		.logout()
        			.logoutUrl("/logout")
        			.and()
//        		.authenticationManager(authenticationManager())
        		.authenticationProvider(authenticationProvider())
                .authorizeRequests()
                	.antMatchers("/login").permitAll()
                	.antMatchers("/logout", "/refresh").hasAuthority("USER")
                	.antMatchers("/admin").hasAnyAuthority("ADMIN")
                	// 그 외
//                	.anyRequest().hasAnyRole()
                	.and()
                .exceptionHandling()
//                	.accessDeniedHandler(accessDeniedHandler())
//                	.authenticationEntryPoint(authenticationEntryPoint())
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
    
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
    	UserDetails admin = User.builder()
    			.passwordEncoder(passwordEncoder()::encode)
    			.username("admin")
    			.password("admin")
    			.authorities("ADMIN")
    			.build();
    	UserDetails test = User.builder()
    			.passwordEncoder(passwordEncoder()::encode)
    			.username("test")
    			.password("test")
    			.authorities("USER")
    			.build();
    	return new InMemoryUserDetailsManager(admin, test);
    }
}
