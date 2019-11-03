package com.example.demo4;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.example.demo4.data.ErrorRS;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration implements ResourceServerConfigurer {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResourceServerConfiguration.class);

	@Autowired
	private TokenStore tokenStore;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources
			.tokenStore(tokenStore)
			.tokenServices(tokenServices())
			.resourceId("api")
		;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatchers()
			.and()
			.csrf().disable()
			.headers().frameOptions().disable()
			.and()
			.authorizeRequests()
				.antMatchers("/h2/**", "/login.html").permitAll()
				.anyRequest().authenticated()
			.and()
			.exceptionHandling()
				.authenticationEntryPoint(authenticationEntryPoint())
			;
	}
	
	@Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore);
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
	
	private AuthenticationEntryPoint authenticationEntryPoint() {
		return new AuthenticationEntryPoint() {
			@Override
			public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) throws IOException, ServletException {
				
				ErrorRS errorRS = new ErrorRS();
				errorRS.setStatus(1);
				errorRS.setError("unauthorized");
				errorRS.setMessage(ex.getMessage());
				errorRS.setPath(req.getServletPath());
				
				res.setContentType("application/json");
				res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				
				ObjectMapper objectMapper = new ObjectMapper();
				objectMapper.writeValue(res.getOutputStream(), errorRS);
				
				LOGGER.error("{}(인증오류): status[{}] path[{}] message[{}]", "unauthorized", 1, req.getServletPath(), ex.getMessage());
			}
		};	
	}
	
//	private Map<String, Object> getExtraInfo(OAuth2Authentication auth) {
//		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
//		OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());
//		return accessToken.getAdditionalInformation();
//	}
}
