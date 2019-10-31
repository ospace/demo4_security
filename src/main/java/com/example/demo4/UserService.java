package com.example.demo4;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.demo4.data.SecurityAuthority;
import com.example.demo4.data.SecurityUser;

//@Component
public class UserService { //implements UserDetailsService {
	private static Logger LOGGER = LoggerFactory.getLogger(UserService.class);
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
//	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		LOGGER.debug("loadUserByUsername begin: username[{}]", username);
		
//		.withUser("admin").password(passwordEncoder().encode("111")).roles("ADMIN")
//		.and() 
//		.withUser("user").password(passwordEncoder().encode("222")).roles("USER")
		
		if(username.equals("user")) {
			return SecurityUser.of("1", "user", passwordEncoder.encode("222"), SecurityAuthority.of("사용자", "USER"));
		}
		
		return null;
	}

}
