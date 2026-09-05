package br.com.github.gtvnv.audit.chain.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "audit_chain_entries", indexes = {
        @Index(name = "idx_audit_chain_actor_seq", columnList = "actor, sequenceNumber"),
        @Index(name = "idx_audit_chain_event_type",  columnList = "eventType")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditChainEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private Instant timestamp;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType eventType;

    @Column(nullable = false)
    private String actor;

    private String sessionJti;
    private String ipAddress;
    private String userAgent;
    private String resourcePath;

    @Column(columnDefinition = "TEXT")
    private String detail;

    // Payload JSON serializado do contexto do evento
    @Column(columnDefinition = "TEXT")
    private String payloadJson;

    // Hash do entry anterior deste ator; "GENESIS" para o primeiro
    @Column(nullable = false)
    private String previousHash;

    // SHA-256(id|timestamp|actor|eventType|payloadJson|previousHash) — imutável
    @Column(nullable = false, unique = true)
    private String selfHash;

    // Ordem global dentro da cadeia do ator
    @Column(nullable = false)
    private Long sequenceNumber;
}
