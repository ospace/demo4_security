package com.example.demo4;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo4.data.ErrorRS;

@RestController
@RequestMapping("/api")
//@CrossOrigin(origins="*")
@Validated
public class Demo4RestController {
	private static final Logger LOGGER = LoggerFactory.getLogger(Demo4RestController.class);
	
	@ExceptionHandler({Exception.class})
	public ErrorRS handleException(HttpServletRequest req, Exception ex) {
		LOGGER.error("{}({}): message[{}]", ex.getClass().getCanonicalName(), req.getRequestURI(), ex.getMessage(), ex);
		return ErrorRS.of(888, "SYSTEM", req.getRequestURI(), ex.getMessage());
	}
	
	// 접근권한 설정: ADMIN 또는 USER 사용
	@PreAuthorize("hasAuthority('ADMIN') or hasAuthority('USER')")
	@GetMapping("/me")
	public Authentication me(final Authentication authentication) {
		Map<String, Object> detail = getExtraInfo(authentication);
		LOGGER.info("detail[{}]", detail);
		return authentication;
	}
	
	public static String getUserId() {
		return getAuthenticationExtraInfo("user_id", String.class);
	}
	
	public static <R> R getAuthenticationExtraInfo(String key, Class<R> clazz) {
		Map<String, ?> extraInfo = getAuthenticationExtraInfo();
		if(null == extraInfo) return null;
		return clazz.cast(extraInfo.get(key));
	}

	public static Map<String, ?> getAuthenticationExtraInfo() {
		return getExtraInfo(getAuthentication());
	}
	
	@SuppressWarnings("unchecked")
	private static Map<String, Object> getExtraInfo(Authentication auth) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails)auth.getDetails();
		return (Map<String, Object>) details.getDecodedDetails();
	}
	
	public static Authentication getAuthentication() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
	    return null == securityContext ? null : securityContext.getAuthentication();
	}
}
