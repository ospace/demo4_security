package com.example.demo4;

import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;


@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(KeyPairFactory.class)
public class AuthorizationServerConfiguration implements AuthorizationServerConfigurer {
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);
	
	@Value("${security.client-id}")
	private String clientId;
	
	@Value("${security.client-secret}")
	private String clientSecret;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticatgionManager;
	
	@Autowired
	private KeyPairFactory keyPairFactory;
	
	@Autowired
	private DataSource dataSource;
	
	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
//		clients
//			.inMemory()
//		    .withClient(clientId)
//		    .secret(passwordEncoder.encode(clientSecret))
//		    .authorizedGrantTypes("password", "refresh_token")
//		    .scopes("read", "write")
//		    .resourceIds("api")
//		    .accessTokenValiditySeconds(60)
//		    .refreshTokenValiditySeconds(120)
//		    ;
	}
	
	@Override
	public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));
		
		endpoints
			.authenticationManager(this.authenticatgionManager)
			.accessTokenConverter(accessTokenConverter())
			.tokenStore(tokenStore())
            .reuseRefreshTokens(false)
			.tokenEnhancer(tokenEnhancerChain)
			.pathMapping("/oauth/token", "/api/login")
			.exceptionTranslator(exceptionTranslator())
			;
	}
	
	@Override
	public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
		oauthServer
			.passwordEncoder(this.passwordEncoder)
			.tokenKeyAccess("permitAll()")
			.checkTokenAccess("isAuthenticated()")
			.allowFormAuthenticationForClients()
			;  
	}

	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new TokenEnhancer() {
			@Override
			public OAuth2AccessToken enhance(OAuth2AccessToken token, OAuth2Authentication auth) {
				//final Map<String, Object> additionalInfo = new HashMap<>();
				//SecurityUser user = (SecurityUser)auth.getPrincipal();
				//if(null != user) {
				//	additionalInfo.put("user_id", user.getId());
				//}
				
				//((DefaultOAuth2AccessToken) token).setAdditionalInformation(additionalInfo);
				
				return token;
			}
		};
	}

	@Bean
	public AccessTokenConverter tokenConverter() {
		return new DefaultAccessTokenConverter() {
			@Override
		    public OAuth2Authentication extractAuthentication(Map<String, ?> claims) {
		        OAuth2Authentication authentication = super.extractAuthentication(claims);
		        authentication.setDetails(claims);
		        return authentication;
		    }
		};
	}
	
	@Bean
	public TokenStore tokenStore() {
		//return new JwtTokenStore(accessTokenConverter());
		return new JdbcTokenStore(dataSource);
	}
	
	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter ret = new JwtAccessTokenConverter();
		//ret.setKeyPair(keyPairFactory.createKeyPair());
		ret.setSigningKey(keyPairFactory.getJwt().getSigningKey());
		return ret;
	}
	
	private WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator() {
		return new DefaultWebResponseExceptionTranslator() {
			@Override
			public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
				ResponseEntity<OAuth2Exception> entity = super.translate(e);
				OAuth2Exception body = entity.getBody();
				HttpStatus status = entity.getStatusCode();


				body.addAdditionalInformation("status", "1");
				//body.addAdditionalInformation("error", body.getOAuth2ErrorCode());
				body.addAdditionalInformation("error", "unauthorized");
				body.addAdditionalInformation("message", body.getMessage());
				body.addAdditionalInformation("timestamp", new Date().toString());
				
				LOGGER.error("{}(인증오류): status[{}] path[{}] message[{}]", "unauthorized", "1", "/api/login", body.getMessage());
				
				return new ResponseEntity<>(body, entity.getHeaders(), status);
			}
			
		};
	}

}
