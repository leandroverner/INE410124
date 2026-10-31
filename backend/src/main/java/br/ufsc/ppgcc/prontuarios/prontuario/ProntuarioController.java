package br.ufsc.ppgcc.prontuarios.prontuario;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.ufsc.ppgcc.prontuarios.crypto.NestedJwtException;
import br.ufsc.ppgcc.prontuarios.crypto.NestedJwtService;
import br.ufsc.ppgcc.prontuarios.keycloak.MedicoChaveService;

@RestController
public class ProntuarioController {

	private static final Duration TOLERANCIA = Duration.ofMinutes(5);

	private final NestedJwtService nested;
	private final MedicoChaveService chaves;
	private final List<Map<String, Object>> prontuarios = new CopyOnWriteArrayList<>();
	private final Set<String> jtisVistos = ConcurrentHashMap.newKeySet();

	public ProntuarioController(NestedJwtService nested, MedicoChaveService chaves) {
		this.nested = nested;
		this.chaves = chaves;
	}

	/**
	 * Recebe o Nested JWT: JWE (ECDH-ES + A128GCM, cty=JWT) contendo o JWS (ES256) do laudo.
	 * O access token do Keycloak (Bearer) autentica o médico; a assinatura JWS prova a autoria do laudo.
	 */
	@PostMapping(value = "/api/prontuarios", consumes = "application/jose")
	public ResponseEntity<Map<String, Object>> receber(@AuthenticationPrincipal Jwt acesso,
			@RequestBody String jwe) throws ParseException {
		SignedJWT jws = nested.decifrar(jwe.trim());

		ECKey chaveMedico = chaves.buscar(acesso.getSubject())
				.orElseThrow(() -> new NestedJwtException("médico sem chave pública registrada"));
		nested.verificarAssinatura(jws, chaveMedico);

		JWTClaimsSet c = jws.getJWTClaimsSet();
		validarClaims(c, acesso);

		Map<String, Object> registro = Map.of(
				"id", UUID.randomUUID().toString(),
				"paciente_id", c.getStringClaim("paciente_id"),
				"diagnostico", c.getStringClaim("diagnostico"),
				"prescricao", c.getStringClaim("prescricao"),
				"medico", acesso.getClaimAsString("preferred_username"),
				"recebido_em", Instant.now().toString());
		prontuarios.add(registro);

		return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
				"status", "ACEITO",
				"id", registro.get("id"),
				"paciente_id", registro.get("paciente_id"),
				"assinado_por", registro.get("medico"),
				"jws_alg", jws.getHeader().getAlgorithm().getName()));
	}

	@GetMapping("/api/prontuarios")
	public List<Map<String, Object>> listar() {
		return prontuarios;
	}

	private void validarClaims(JWTClaimsSet c, Jwt acesso) throws ParseException {
		if (!acesso.getSubject().equals(c.getSubject())) {
			throw new NestedJwtException("'sub' do laudo difere do médico autenticado");
		}
		Instant agora = Instant.now();
		if (c.getIssueTime() == null || c.getExpirationTime() == null
				|| c.getIssueTime().toInstant().isAfter(agora.plus(TOLERANCIA))
				|| c.getExpirationTime().toInstant().isBefore(agora)) {
			throw new NestedJwtException("laudo expirado ou sem iat/exp");
		}
		if (c.getJWTID() == null || !jtisVistos.add(c.getJWTID())) {
			throw new NestedJwtException("jti ausente ou repetido (replay)");
		}
		for (String campo : List.of("paciente_id", "diagnostico", "prescricao")) {
			if (c.getStringClaim(campo) == null || c.getStringClaim(campo).isBlank()) {
				throw new NestedJwtException("campo obrigatório ausente: " + campo);
			}
		}
	}
}
