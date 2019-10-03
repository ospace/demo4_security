package com.example.demo4;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins="*")
@Validated
public class Demo4RestController {
	private static final Logger LOGGER = LoggerFactory.getLogger(Demo4RestController.class);
	
	@ExceptionHandler({Exception.class})
	public ErrorRS handleException(HttpServletRequest req, Exception ex) {
		LOGGER.error("{}({}): message[{}]", ex.getClass().getCanonicalName(), req.getRequestURI(), ex.getMessage(), ex);
		return ErrorRS.of(888, "SYSTEM", req.getRequestURI(), ex.getMessage());
	}
	
	@GetMapping("/me")
	public Authentication me(final Authentication authentication) {
		Map<String, Object> detail = getExtraInfo(authentication);
		LOGGER.info("detail[{}]", detail);
		return authentication;
	}
	
	private static Map<String, Object> getExtraInfo(Authentication auth) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails)auth.getDetails();
		return (Map<String, Object>) details.getDecodedDetails();
	}
	
}
