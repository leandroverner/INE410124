package br.ufsc.ppgcc.prontuarios.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import br.ufsc.ppgcc.prontuarios.config.AppProperties;

/**
 * Par de chaves EC P-256 estático do servidor (nB, PB) usado no ECDH-ES.
 * É gerado na primeira execução e persistido em arquivo.
 */
@Component
public class ServerKeyProvider {

	private final ECKey key;

	@Autowired
	public ServerKeyProvider(AppProperties props) throws IOException, ParseException, JOSEException {
		this(Path.of(props.serverKeyFile()));
	}

	public ServerKeyProvider(Path file) throws IOException, ParseException, JOSEException {
		if (Files.exists(file)) {
			this.key = ECKey.parse(Files.readString(file, StandardCharsets.UTF_8));
		}
		else {
			this.key = new ECKeyGenerator(Curve.P_256)
					.keyUse(KeyUse.ENCRYPTION)
					.keyIDFromThumbprint(true)
					.generate();
			if (file.getParent() != null) {
				Files.createDirectories(file.getParent());
			}
			Files.writeString(file, key.toJSONString(), StandardCharsets.UTF_8);
		}
	}

	public ECKey privateKey() {
		return key;
	}

	public ECKey publicKey() {
		return key.toPublicJWK();
	}
}
