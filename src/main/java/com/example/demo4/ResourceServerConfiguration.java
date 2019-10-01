package com.example.demo4;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.cors.CorsUtils;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration implements ResourceServerConfigurer {
	private static final String ROOT_PATTERN = "/**";
	
	@Autowired
	private TokenStore tokenStore;
	
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore)
		;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http//.requestMatchers()
			//.and()
			//.csrf().disable()
			.authorizeRequests()
				//.requestMatchers(CorsUtils::isPreFlightRequest).permitAll() 
				.antMatchers(HttpMethod.OPTIONS, "/api/login").permitAll()
				//.antMatchers(ROOT_PATTERN).authenticated()
				
			;
	}
}
