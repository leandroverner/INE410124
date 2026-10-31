package br.ufsc.ppgcc.prontuarios.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProperties(Cors cors, String serverKeyFile, Keycloak keycloak) {

	public record Cors(String allowedOrigin) {
	}

	public record Keycloak(String baseUrl, String realm, String adminClientId, String adminClientSecret,
			String publicKeyAttribute) {
	}
}
