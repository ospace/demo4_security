package com.example.demo4.data;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class SecurityUser implements UserDetails {
	private static final long serialVersionUID = 1L;

	private String id;
	private String username;
	private String password;
	private List<SecurityAuthority> authorities;
	
	public static SecurityUser of(String id, String username, String password, SecurityAuthority authority) {
		return new SecurityUser(id, username, password, Arrays.asList(authority));
	}

	public SecurityUser(String id, String username, String password, List<SecurityAuthority> authorities) {
		this.id = id;
		this.username = username;
		this.password = password;
		this.authorities = authorities;
	}

	public String getId() {
		return id;
	}

	public SecurityAuthority getAuthority(int index) {
		return null == authorities ? null : authorities.get(index);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
