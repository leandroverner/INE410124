package br.ufsc.ppgcc.prontuarios.crypto;

import java.text.ParseException;
import java.util.Set;

import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

/**
 * Processa o Nested JWT (sign-then-encrypt): decifra o JWE (ECDH-ES) e valida o JWS interno (ES256).
 */
@Service
public class NestedJwtService {

	private static final Set<EncryptionMethod> ENC_PERMITIDOS = Set.of(EncryptionMethod.A128GCM,
			EncryptionMethod.A256GCM);

	private final ServerKeyProvider serverKey;

	public NestedJwtService(ServerKeyProvider serverKey) {
		this.serverKey = serverKey;
	}

	/** Decifra o JWE compacto de 5 partes e devolve o JWS (3 partes) ainda não verificado. */
	public SignedJWT decifrar(String jweCompacto) {
		try {
			JWEObject jwe = JWEObject.parse(jweCompacto);
			JWEHeader h = jwe.getHeader();

			if (!JWEAlgorithm.ECDH_ES.equals(h.getAlgorithm())) {
				throw new NestedJwtException("alg deve ser ECDH-ES");
			}
			if (!ENC_PERMITIDOS.contains(h.getEncryptionMethod())) {
				throw new NestedJwtException("enc deve ser A128GCM ou A256GCM");
			}
			if (!"JWT".equalsIgnoreCase(h.getContentType())) {
				throw new NestedJwtException("cty deve ser JWT (token aninhado)");
			}
			if (!(h.getEphemeralPublicKey() instanceof ECKey epk) || !Curve.P_256.equals(epk.getCurve())) {
				throw new NestedJwtException("epk ausente ou fora da curva P-256");
			}

			ECDHDecrypter decrypter = new ECDHDecrypter(serverKey.privateKey());
			jwe.decrypt(decrypter);

			return SignedJWT.parse(jwe.getPayload().toString());
		}
		catch (ParseException | JOSEException e) {
			throw new NestedJwtException("JWE inválido: " + e.getMessage(), e);
		}
	}

	/** Verifica a assinatura ES256 do JWS interno com a chave pública do médico. */
	public void verificarAssinatura(SignedJWT jws, ECKey chavePublicaMedico) {
		try {
			if (!JWSAlgorithm.ES256.equals(jws.getHeader().getAlgorithm())) {
				throw new NestedJwtException("JWS interno deve usar ES256");
			}
			if (!jws.verify(new ECDSAVerifier(chavePublicaMedico))) {
				throw new NestedJwtException("assinatura JWS inválida");
			}
		}
		catch (JOSEException e) {
			throw new NestedJwtException("falha ao verificar JWS: " + e.getMessage(), e);
		}
	}
}
