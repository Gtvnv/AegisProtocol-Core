package br.com.github.gtvnv.retention.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Prova de que um lote de entries do Ômega foi arquivado: qual faixa de
 * sequenceNumber, em qual arquivo, com qual checksum. As entries originais
 * continuam intactas em audit_chain_entries — isto é só o recibo.
 *
 * checkpointHash = SHA-256(actor|fromSequence|toSequence|archiveChecksum|
 * selfHash da última entry do lote) — permite provar depois que o
 * checkpoint não foi forjado nem alterado, sem depender só do timestamp.
 */
@Entity
@Table(name = "retention_checkpoints")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RetentionCheckpoint {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String actor;

    @Column(nullable = false)
    private long fromSequence;

    @Column(nullable = false)
    private long toSequence;

    @Column(nullable = false)
    private int entryCount;

    @Column(nullable = false)
    private String archiveFile;

    @Column(nullable = false)
    private String archiveChecksum;

    @Column(nullable = false)
    private String lastEntrySelfHash;

    @Column(nullable = false)
    private String checkpointHash;

    @Column(nullable = false)
    private Instant createdAt;

    /**
     * Null até o purge físico do arquivo + das linhas cobertas por este
     * checkpoint ser executado manualmente por um DBA (ver docs/retention-purge-runbook.md)
     * e então registrado via RetentionEngineService#markPurged. Este campo
     * NUNCA é setado por código de purge automático — este satélite não
     * apaga nada sozinho, só dá o recibo de que alguém apagou por fora.
     */
    private Instant purgedAt;

    private String purgedBy;
}
