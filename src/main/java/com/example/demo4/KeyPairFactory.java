package com.example.demo4;

import java.security.KeyPair;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@ConfigurationProperties("security")
public class KeyPairFactory {
	private JwtProperties jwt;
	
	public static class JwtProperties {
		private String   signingKey;
		private Resource keyStore;
		private String   keyStorePassword;
		private String   keyPairAlias;
		private String   keyPairPassword;
		
		public String getSigningKey() {
			return signingKey;
		}
		public void setSigningKey(String signingKey) {
			this.signingKey = signingKey;
		}
		public Resource getKeyStore() {
			return keyStore;
		}
		public void setKeyStore(Resource keyStore) {
			this.keyStore = keyStore;
		}
		public String getKeyStorePassword() {
			return keyStorePassword;
		}
		public void setKeyStorePassword(String keyStorePassword) {
			this.keyStorePassword = keyStorePassword;
		}
		public String getKeyPairAlias() {
			return keyPairAlias;
		}
		public void setKeyPairAlias(String keyPairAlias) {
			this.keyPairAlias = keyPairAlias;
		}
		public String getKeyPairPassword() {
			return keyPairPassword;
		}
		public void setKeyPairPassword(String keyPairPassword) {
			this.keyPairPassword = keyPairPassword;
		}
	}

	public JwtProperties getJwt() {
		return jwt;
	}

	public void setJwt(JwtProperties jwt) {
		this.jwt = jwt;
	}
	
	public KeyPair createKeyPair() {
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(getJwt().getKeyStore(), getJwt().getKeyStorePassword().toCharArray());
		return keyStoreKeyFactory.getKeyPair(getJwt().getKeyPairAlias(), getJwt().getKeyPairPassword().toCharArray());
	}
}
