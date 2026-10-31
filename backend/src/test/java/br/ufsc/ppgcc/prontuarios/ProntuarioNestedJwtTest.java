package br.ufsc.ppgcc.prontuarios;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.ufsc.ppgcc.prontuarios.keycloak.MedicoChaveService;

@SpringBootTest
@AutoConfigureMockMvc
class ProntuarioNestedJwtTest {

	private static final String SUB = "11111111-2222-3333-4444-555555555555";
	private static final Path KEY_FILE = Path.of(System.getProperty("java.io.tmpdir"),
			"prontuarios-test-" + UUID.randomUUID() + ".jwk");

	@DynamicPropertySource
	static void props(DynamicPropertyRegistry r) {
		r.add("app.server-key-file", KEY_FILE::toString);
	}

	@Autowired MockMvc mvc;
	@MockitoBean MedicoChaveService chaves;

	ECKey medico;
	ECKey servidorPublica;

	@BeforeEach
	void setup() throws Exception {
		medico = new ECKeyGenerator(Curve.P_256).keyID("medico").generate();
		org.mockito.Mockito.when(chaves.buscar(SUB)).thenReturn(Optional.of(medico.toPublicJWK()));
		String json = mvc.perform(get("/api/chave-publica")).andReturn().getResponse().getContentAsString();
		servidorPublica = ECKey.parse(
				com.nimbusds.jose.util.JSONObjectUtils.parse(json).get("keys") instanceof java.util.List<?> l
						? com.nimbusds.jose.util.JSONObjectUtils.toJSONString(
								(java.util.Map<String, Object>) l.get(0))
						: null);
	}

	private RequestPostProcessor acesso() {
		return jwt().jwt(j -> j.subject(SUB).claim("preferred_username", "dr.silva"));
	}

	private String jws(ECKey chaveAssinatura, String jti, Date exp) throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.subject(SUB).jwtID(jti).issueTime(new Date()).expirationTime(exp)
				.claim("paciente_id", "P-1001")
				.claim("diagnostico", "Hipertensão arterial")
				.claim("prescricao", "Losartana 50mg")
				.build();
		SignedJWT s = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(chaveAssinatura.getKeyID()).build(),
				claims);
		s.sign(new ECDSASigner(chaveAssinatura));
		return s.serialize();
	}

	private String jwe(String conteudo, JWEAlgorithm alg) throws Exception {
		JWEObject o = new JWEObject(
				new JWEHeader.Builder(alg, EncryptionMethod.A128GCM).contentType("JWT").build(),
				new Payload(conteudo));
		o.encrypt(new ECDHEncrypter(servidorPublica));
		return o.serialize();
	}

	private String valido() throws Exception {
		return jwe(jws(medico, UUID.randomUUID().toString(), new Date(System.currentTimeMillis() + 300_000)),
				JWEAlgorithm.ECDH_ES);
	}

	@Test
	void aceitaNestedJwtValido() throws Exception {
		String token = valido();
		org.junit.jupiter.api.Assertions.assertEquals(5, token.split("\\.", -1).length);
		org.junit.jupiter.api.Assertions.assertTrue(token.split("\\.", -1)[1].isEmpty(), "EncryptedKey vazio em ECDH-ES direto");
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(token))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.status").value("ACEITO"))
				.andExpect(jsonPath("$.assinado_por").value("dr.silva"));
	}

	@Test
	void rejeitaSemAccessToken() throws Exception {
		mvc.perform(post("/api/prontuarios").contentType("application/jose").content(valido()))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void rejeitaAssinaturaDeOutraChave() throws Exception {
		ECKey intruso = new ECKeyGenerator(Curve.P_256).generate();
		String forjado = jwe(jws(intruso, UUID.randomUUID().toString(), new Date(System.currentTimeMillis() + 300_000)),
				JWEAlgorithm.ECDH_ES);
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(forjado))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.erro").value("assinatura JWS inválida"));
	}

	@Test
	void rejeitaReplay() throws Exception {
		String jti = UUID.randomUUID().toString();
		String t1 = jwe(jws(medico, jti, new Date(System.currentTimeMillis() + 300_000)), JWEAlgorithm.ECDH_ES);
		String t2 = jwe(jws(medico, jti, new Date(System.currentTimeMillis() + 300_000)), JWEAlgorithm.ECDH_ES);
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(t1))
				.andExpect(status().isCreated());
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(t2))
				.andExpect(status().isUnprocessableEntity());
	}

	@Test
	void rejeitaLaudoExpirado() throws Exception {
		String t = jwe(jws(medico, UUID.randomUUID().toString(), new Date(System.currentTimeMillis() - 1000)),
				JWEAlgorithm.ECDH_ES);
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(t))
				.andExpect(status().isUnprocessableEntity());
	}

	@Test
	void rejeitaJweCorrompido() throws Exception {
		String t = valido();
		String adulterado = t.substring(0, t.length() - 4) + (t.endsWith("AAAA") ? "BBBB" : "AAAA");
		mvc.perform(post("/api/prontuarios").with(acesso()).contentType("application/jose").content(adulterado))
				.andExpect(status().isUnprocessableEntity());
	}
}
