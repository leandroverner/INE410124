package br.ufsc.ppgcc.prontuarios.crypto;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChavePublicaController {

	private final ServerKeyProvider serverKey;

	public ChavePublicaController(ServerKeyProvider serverKey) {
		this.serverKey = serverKey;
	}

	/** JWK Set com a chave pública estática do servidor (PB), usada pelo cliente no ECDH-ES. */
	@GetMapping(value = "/api/chave-publica", produces = "application/jwk-set+json")
	public Map<String, Object> jwks() {
		return Map.of("keys", java.util.List.of(serverKey.publicKey().toJSONObject()));
	}
}
