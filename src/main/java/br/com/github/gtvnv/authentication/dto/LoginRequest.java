package br.com.github.gtvnv.authentication.dto;

/**
 * consentVersion é OPCIONAL — só é exigido quando o titular não tem
 * consentimento válido na versão vigente (ver AuthService#login e o
 * satélite Consent Gate). Login normal, com consentimento em dia, não
 * precisa preenchê-lo.
 */
public record LoginRequest(String username, String password, String consentVersion) {

    public LoginRequest(String username, String password) {
        this(username, password, null);
    }
}
