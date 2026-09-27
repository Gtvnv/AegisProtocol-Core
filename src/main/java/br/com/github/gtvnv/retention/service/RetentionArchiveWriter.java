package br.com.github.gtvnv.retention.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.retention.config.RetentionProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Serializa um lote de AuditChainEntry em NDJSON (um JSON por linha, fácil
 * de auditar/grep/importar depois) e calcula o checksum do arquivo — é esse
 * checksum que o RetentionCheckpoint guarda como prova de integridade.
 */
@Component
@RequiredArgsConstructor
public class RetentionArchiveWriter {

    private final RetentionProperties properties;
    private final ObjectMapper objectMapper;

    public record WrittenArchive(Path file, String checksum) {}

    public WrittenArchive write(String actor, List<AuditChainEntry> entries) throws IOException {
        Path dir = Path.of(properties.getArchiveDir(), sanitize(actor));
        Files.createDirectories(dir);

        long from = entries.get(0).getSequenceNumber();
        long to = entries.get(entries.size() - 1).getSequenceNumber();
        Path file = dir.resolve("%d-%d-%d.ndjson".formatted(from, to, Instant.now().toEpochMilli()));

        StringBuilder ndjson = new StringBuilder();
        for (AuditChainEntry entry : entries) {
            ndjson.append(objectMapper.writeValueAsString(entry)).append('\n');
        }
        String content = ndjson.toString();
        Files.writeString(file, content, StandardCharsets.UTF_8);

        return new WrittenArchive(file, sha256Hex(content));
    }

    /** Recalcula o checksum de um arquivo já escrito — usado na verificação. */
    public String checksumOf(Path file) throws IOException {
        return sha256Hex(Files.readString(file, StandardCharsets.UTF_8));
    }

    private String sha256Hex(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }

    private String sanitize(String actor) {
        return actor.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
