package br.com.github.gtvnv.audit.chain.dto;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;

import java.time.Instant;

/**
 * Projeção read-only de AuditChainEntry para exposição via API.
 * selfHash e previousHash são incluídos para permitir verificação independente pelo cliente.
 */
public record AuditChainEntryDto(
        String id,
        Instant timestamp,
        AuditEventType eventType,
        String actor,
        String sessionJti,
        String ipAddress,
        String resourcePath,
        String detail,
        String previousHash,
        String selfHash,
        long sequenceNumber
) {
    public static AuditChainEntryDto from(AuditChainEntry e) {
        return new AuditChainEntryDto(
                e.getId(),
                e.getTimestamp(),
                e.getEventType(),
                e.getActor(),
                e.getSessionJti(),
                e.getIpAddress(),
                e.getResourcePath(),
                e.getDetail(),
                e.getPreviousHash(),
                e.getSelfHash(),
                e.getSequenceNumber()
        );
    }
}
