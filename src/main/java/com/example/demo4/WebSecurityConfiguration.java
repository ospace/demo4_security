package com.example.demo4;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

//https://howtodoinjava.com/spring5/webmvc/spring-mvc-cors-configuration/

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private UserService userService;
	
	@Override
	protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService)
//		auth.inMemoryAuthentication()
//			.withUser("admin").password(passwordEncoder().encode("111")).roles("ADMIN")
//			.and() 
//			.withUser("user").password(passwordEncoder().encode("222")).roles("USER")
		;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.csrf()
			.disable()
			;
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
