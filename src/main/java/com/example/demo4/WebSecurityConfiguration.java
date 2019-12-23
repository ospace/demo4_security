package com.example.demo4;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

//https://howtodoinjava.com/spring5/webmvc/spring-mvc-cors-configuration/

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
	private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfiguration.class);
	
//	@Autowired
//	private UserService userService;
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Override
	protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
			.usersByUsernameQuery("select username, password, enabled from _users where username=?")
			.authoritiesByUsernameQuery("select username, authority from authorities where username=?")
			.passwordEncoder(passwordEncoder)
//		auth.userDetailsService(userService)
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
			.formLogin()
//			.and()
//			.oauth2Login()
			;
	}
	
	@Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
	
	//https://www.baeldung.com/spring-events
	@Bean
	public ApplicationListener<?> authenticationSuccessHandler() {
		return new ApplicationListener<AbstractAuthenticationEvent> () {
			@Override
			public void onApplicationEvent(AbstractAuthenticationEvent ev) {
				//if (ev.getAuthentication().getPrincipal() instanceof SecurityUser) {
					//SecurityUser user = (SecurityUser) ev.getAuthentication().getPrincipal();
					//LOGGER.info("사용자가 로그인하였습니다 ({} / {} / 권한 : {})", user.getUsername(), user.getCustomerName(), user.getAuthority(0).getName());
					LOGGER.info("사용자가 로그인하였습니다 ({})", ev.getAuthentication());
				//}
			}
		};
	}

	@Bean
	public ApplicationListener<?> authenticationFailureHandler() {
		return new ApplicationListener<AuthenticationFailureBadCredentialsEvent>() {
			@Override
			public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent ev) {
				//SecurityUser user = userDetailsManager.loadUserByUsername(ev.getAuthentication().getName());
				//LOGGER.info("사용자가 로그인에 실패했습니다 ({} / {} / 권한 : {})", user.getUsername(), user.getCustomerName(), user.getAuthority(0).getName());
				LOGGER.info("사용자가 로그인에 실패했습니다 ({} / {} / 권한 : {})", ev.getAuthentication());
			}
		};
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
