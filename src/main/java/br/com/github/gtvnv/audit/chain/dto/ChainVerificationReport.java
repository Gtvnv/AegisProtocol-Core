package br.com.github.gtvnv.audit.chain.dto;

import java.time.Instant;

/**
 * Resultado de uma verificação de integridade da cadeia de auditoria.
 *
 * @param actor         Ator cujos entries foram verificados ("*" para verificação global)
 * @param totalEntries  Total de entries analisados
 * @param isValid       true se toda a cadeia está íntegra
 * @param firstBrokenAt ID do primeiro entry com hash adulterado (null se íntegro)
 * @param verifiedAt    Instante da verificação
 */
public record ChainVerificationReport(
        String actor,
        long totalEntries,
        boolean isValid,
        String firstBrokenAt,
        Instant verifiedAt
) {
    public static ChainVerificationReport valid(String actor, long total) {
        return new ChainVerificationReport(actor, total, true, null, Instant.now());
    }

    public static ChainVerificationReport broken(String actor, long total, String firstBrokenId) {
        return new ChainVerificationReport(actor, total, false, firstBrokenId, Instant.now());
    }
}
