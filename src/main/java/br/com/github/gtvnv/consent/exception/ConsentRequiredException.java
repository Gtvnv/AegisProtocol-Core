package br.com.github.gtvnv.consent.exception;

import lombok.Getter;

/**
 * Satélite Consent Gate — lançada quando o titular não tem consentimento
 * válido na versão vigente e precisa reconsentir antes de continuar
 * autenticado (login) ou renovar sessão (refresh).
 */
@Getter
public class ConsentRequiredException extends RuntimeException {

    private final String requiredVersion;

    public ConsentRequiredException(String message, String requiredVersion) {
        super(message);
        this.requiredVersion = requiredVersion;
    }
}
