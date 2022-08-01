package com.devh.project.authserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
//@EnableWebSecurity
public class SpringSecurityConfiguration {
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	// Configuring HttpSecurity
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.formLogin()
//				.loginPage("/login")
				.and()
			.authorizeHttpRequests((authz) -> authz
					.anyRequest().authenticated());
		return http.build();
	}
	
//	// Configuring WebSecurity
//	@Bean
//	public WebSecurityCustomizer webSecurityCustomizer() {
//		return (web) -> web
//				.ignoring().antMatchers("/login", "/signup");
//	}
//	
//	// In-Memory Authentication
//	@Bean
//	public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//		UserDetails testUser = User.withDefaultPasswordEncoder()
//				.username("test")
//				.password("test")
//				.roles("USER")
//				.build();
//		UserDetails adminUser = User.withDefaultPasswordEncoder()
//				.username("admin")
//				.password("admin")
//				.roles("ADMIN")
//				.build();
//		return new InMemoryUserDetailsManager(testUser, adminUser);
//	}
	
}
