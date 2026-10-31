package br.ufsc.ppgcc.prontuarios.config;

import java.text.ParseException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import br.ufsc.ppgcc.prontuarios.crypto.NestedJwtException;

@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler(NestedJwtException.class)
	ResponseEntity<Map<String, String>> nested(NestedJwtException e) {
		return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(Map.of("erro", e.getMessage()));
	}

	@ExceptionHandler(ParseException.class)
	ResponseEntity<Map<String, String>> parse(ParseException e) {
		return ResponseEntity.badRequest().body(Map.of("erro", "formato inválido: " + e.getMessage()));
	}
}
