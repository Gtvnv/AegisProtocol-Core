package br.com.github.gtvnv.retention.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.retention.config.RetentionProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RetentionArchiveWriterTest {

    @TempDir
    Path tempDir;

    private RetentionArchiveWriter writer;

    @BeforeEach
    void setUp() {
        RetentionProperties properties = new RetentionProperties();
        properties.setArchiveDir(tempDir.toString());
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        writer = new RetentionArchiveWriter(properties, objectMapper);
    }

    private AuditChainEntry entry(long seq) {
        return AuditChainEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .eventType(AuditEventType.LOGIN_SUCCESS)
                .actor("alice")
                .sequenceNumber(seq)
                .previousHash("prev-" + seq)
                .selfHash("hash-" + seq)
                .build();
    }

    @Test
    @DisplayName("write() grava um NDJSON com uma linha por entry, na pasta do ator")
    void write_CreatesOneNdjsonLinePerEntry() throws IOException {
        List<AuditChainEntry> batch = List.of(entry(1), entry(2), entry(3));

        RetentionArchiveWriter.WrittenArchive archive = writer.write("alice", batch);

        assertThat(Files.exists(archive.file())).isTrue();
        assertThat(archive.file().getParent().getFileName().toString()).isEqualTo("alice");
        List<String> lines = Files.readAllLines(archive.file());
        assertThat(lines).hasSize(3);
        assertThat(lines.get(0)).contains("\"hash-1\"");
        assertThat(lines.get(2)).contains("\"hash-3\"");
    }

    @Test
    @DisplayName("checksumOf() recalcula o mesmo checksum retornado por write() para o mesmo conteúdo")
    void checksumOf_MatchesWriteChecksum() throws IOException {
        List<AuditChainEntry> batch = List.of(entry(1), entry(2));

        RetentionArchiveWriter.WrittenArchive archive = writer.write("alice", batch);
        String recomputed = writer.checksumOf(archive.file());

        assertThat(recomputed).isEqualTo(archive.checksum());
    }

    @Test
    @DisplayName("checksumOf() muda se o arquivo arquivado for adulterado depois")
    void checksumOf_DetectsTampering() throws IOException {
        RetentionArchiveWriter.WrittenArchive archive = writer.write("alice", List.of(entry(1)));
        String original = archive.checksum();

        Files.writeString(archive.file(), "linha adulterada\n", java.nio.file.StandardOpenOption.APPEND);
        String afterTampering = writer.checksumOf(archive.file());

        assertThat(afterTampering).isNotEqualTo(original);
    }

    @Test
    @DisplayName("Nomes de ator com caracteres não seguros para caminho são sanitizados")
    void write_SanitizesUnsafeActorNameForPath() throws IOException {
        RetentionArchiveWriter.WrittenArchive archive = writer.write("10.0.0.1:8443", List.of(entry(1)));

        assertThat(Files.exists(archive.file())).isTrue();
        assertThat(archive.file().getParent().getFileName().toString()).doesNotContain(":");
    }
}
