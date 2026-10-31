package br.ufsc.ppgcc.prontuarios.keycloak;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import com.nimbusds.jose.jwk.ECKey;

import br.ufsc.ppgcc.prontuarios.config.AppProperties;

/**
 * Persiste a chave pública do médico como atributo do usuário no Keycloak (Admin API),
 * de modo que o Keycloak seja a âncora de confiança das identidades.
 */
@Service
public class KeycloakMedicoChaveService implements MedicoChaveService {

	private static final ParameterizedTypeReference<Map<String, Object>> MAP = new ParameterizedTypeReference<>() {
	};

	private final AppProperties.Keycloak cfg;
	private final RestClient http = RestClient.create();

	public KeycloakMedicoChaveService(AppProperties props) {
		this.cfg = props.keycloak();
	}

	@Override
	@SuppressWarnings("unchecked")
	public void registrar(String sub, ECKey chavePublica) {
		Map<String, Object> user = new HashMap<>(usuario(sub));
		Map<String, Object> attrs = new HashMap<>();
		if (user.get("attributes") instanceof Map<?, ?> existentes) {
			attrs.putAll((Map<String, Object>) existentes);
		}
		attrs.put(cfg.publicKeyAttribute(), List.of(chavePublica.toPublicJWK().toJSONString()));
		user.put("attributes", attrs);

		http.put().uri(usuarioUri(sub))
				.headers(h -> h.setBearerAuth(tokenAdmin()))
				.contentType(MediaType.APPLICATION_JSON)
				.body(user)
				.retrieve().toBodilessEntity();
	}

	@Override
	public Optional<ECKey> buscar(String sub) {
		Object attrs = usuario(sub).get("attributes");
		if (attrs instanceof Map<?, ?> m && m.get(cfg.publicKeyAttribute()) instanceof List<?> valores
				&& !valores.isEmpty()) {
			try {
				return Optional.of(ECKey.parse(valores.get(0).toString()));
			}
			catch (ParseException e) {
				return Optional.empty();
			}
		}
		return Optional.empty();
	}

	private Map<String, Object> usuario(String sub) {
		return http.get().uri(usuarioUri(sub))
				.headers(h -> h.setBearerAuth(tokenAdmin()))
				.retrieve().body(MAP);
	}

	private String usuarioUri(String sub) {
		return cfg.baseUrl() + "/admin/realms/" + cfg.realm() + "/users/" + sub;
	}

	private String tokenAdmin() {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("grant_type", "client_credentials");
		form.add("client_id", cfg.adminClientId());
		form.add("client_secret", cfg.adminClientSecret());
		Map<String, Object> resp = http.post()
				.uri(cfg.baseUrl() + "/realms/" + cfg.realm() + "/protocol/openid-connect/token")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(form)
				.retrieve().body(MAP);
		return (String) resp.get("access_token");
	}
}
