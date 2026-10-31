package br.ufsc.ppgcc.prontuarios.keycloak;

import java.util.Optional;

import com.nimbusds.jose.jwk.ECKey;

/** Guarda a chave pública ES256 de cada médico, vinculada ao 'sub' do Keycloak. */
public interface MedicoChaveService {

	void registrar(String sub, ECKey chavePublica);

	Optional<ECKey> buscar(String sub);
}
