package br.ufsc.ppgcc.prontuarios.crypto;

public class NestedJwtException extends RuntimeException {

	public NestedJwtException(String message) {
		super(message);
	}

	public NestedJwtException(String message, Throwable cause) {
		super(message, cause);
	}
}
