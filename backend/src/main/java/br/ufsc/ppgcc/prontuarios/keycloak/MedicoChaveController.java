package br.ufsc.ppgcc.prontuarios.keycloak;

import java.text.ParseException;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

@RestController
public class MedicoChaveController {

	private final MedicoChaveService chaves;

	public MedicoChaveController(MedicoChaveService chaves) {
		this.chaves = chaves;
	}

	/** Registra a chave pública ES256 do médico autenticado (a privada nunca sai do navegador). */
	@PutMapping(value = "/api/medico/chave-publica", consumes = "application/json")
	public ResponseEntity<?> registrar(@AuthenticationPrincipal Jwt token, @RequestBody String jwk)
			throws ParseException {
		ECKey chave = ECKey.parse(jwk);
		if (chave.isPrivate()) {
			return ResponseEntity.badRequest().body(Map.of("erro", "envie somente a chave pública"));
		}
		if (!Curve.P_256.equals(chave.getCurve())) {
			return ResponseEntity.badRequest().body(Map.of("erro", "a chave deve ser EC P-256"));
		}
		chaves.registrar(token.getSubject(), chave);
		return ResponseEntity.ok(Map.of("sub", token.getSubject(), "kid", String.valueOf(chave.getKeyID())));
	}

	@GetMapping("/api/medico/chave-publica")
	public ResponseEntity<?> consultar(@AuthenticationPrincipal Jwt token) {
		return chaves.buscar(token.getSubject())
				.<ResponseEntity<?>>map(k -> ResponseEntity.ok(k.toJSONObject()))
				.orElse(ResponseEntity.notFound().build());
	}
}
