package com.example.demo4.data;

import org.springframework.security.core.GrantedAuthority;

public class SecurityAuthority implements GrantedAuthority {
	private static final long serialVersionUID = 1L;
	
	private String name;
	private String code;
	
	public static SecurityAuthority of(String name, String code) {
		return new SecurityAuthority(name, code);
	}
	
	public SecurityAuthority(String name, String code) {
		this.name = name;
		this.code = code;
	}
	
	public String getName() {
		return name;
	}

	@Override
	public String getAuthority() {
		return code;
	}
}
