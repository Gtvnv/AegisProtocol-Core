package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Motor de hash SHA-256 determinístico para a cadeia de auditoria.
 * Sem dependências de Spring além do @Component — testável como POJO puro.
 *
 * Formato de entrada:
 *   id|timestampEpochMillis|actor|eventType|payloadJson|previousHash
 * Campos separados por '|'. Nenhum campo pode ser null.
 */
@Component
public class AuditHashEngine {

    private static final String ALGORITHM = "SHA-256";
    private static final String SEPARATOR = "|";

    public String compute(String id,
                          Instant timestamp,
                          String actor,
                          AuditEventType eventType,
                          String payloadJson,
                          String previousHash) {

        String input = id + SEPARATOR
                + timestamp.toEpochMilli() + SEPARATOR
                + actor + SEPARATOR
                + eventType.name() + SEPARATOR
                + payloadJson + SEPARATOR
                + previousHash;

        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 é garantido pela JVM spec (java.security) — nunca lançado
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }
}
