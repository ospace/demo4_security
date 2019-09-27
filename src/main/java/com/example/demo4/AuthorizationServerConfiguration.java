package com.example.demo4;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;


@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(KeyPairFactory.class)
public class AuthorizationServerConfiguration implements AuthorizationServerConfigurer {
	
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
	
	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
		    .withClient(clientId)
		    .secret(passwordEncoder.encode(clientSecret))
		    .authorizedGrantTypes("password")
		    .scopes("read", "write")
		    ;
	}
	
	@Override
	public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints
			.authenticationManager(this.authenticatgionManager)
			.accessTokenConverter(jwtAccessTokenConverter())
			//.userDetailsService(userDetailsManager)
			.tokenStore(tokenStore())
			.allowedTokenEndpointRequestMethods(HttpMethod.POST)
			.pathMapping("/oauth/token", "/api/login")
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
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter ret = new JwtAccessTokenConverter();
		//ret.setKeyPair(keyPairFactory.createKeyPair());
		ret.setSigningKey(keyPairFactory.getJwt().getSigningKey());
		return ret;
	}
}
