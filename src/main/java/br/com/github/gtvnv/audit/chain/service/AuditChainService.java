package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Orquestra a escrita atômica e encadeada na audit_chain_entries.
 *
 * Fluxo por append:
 *  1. Adquire PESSIMISTIC_WRITE no último entry do ator (serializa escritas por ator)
 *  2. Calcula previousHash e próximo sequenceNumber
 *  3. Serializa payload para JSON
 *  4. Computa selfHash via AuditHashEngine
 *  5. Persiste numa transação REQUIRES_NEW (independente da transação chamadora)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditChainService {

    private static final String GENESIS = "GENESIS";

    private final AuditChainRepository repository;
    private final AuditHashEngine hashEngine;
    private final ObjectMapper objectMapper;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditChainEntry append(AuditEventType eventType,
                                  String actor,
                                  String sessionJti,
                                  String ipAddress,
                                  String userAgent,
                                  String resourcePath,
                                  String detail,
                                  Map<String, Object> payload) {
        try {
            AuditChainEntry last = repository
                    .findFirstByActorOrderBySequenceNumberDesc(actor)
                    .orElse(null);

            String previousHash  = last != null ? last.getSelfHash()      : GENESIS;
            long   sequenceNumber = last != null ? last.getSequenceNumber() + 1 : 1L;

            String id          = UUID.randomUUID().toString();
            Instant timestamp  = Instant.now();
            String payloadJson = serializePayload(payload);

            String selfHash = hashEngine.compute(id, timestamp, actor, eventType, payloadJson, previousHash);

            AuditChainEntry entry = AuditChainEntry.builder()
                    .id(id)
                    .timestamp(timestamp)
                    .eventType(eventType)
                    .actor(actor)
                    .sessionJti(sessionJti)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .resourcePath(resourcePath)
                    .detail(detail)
                    .payloadJson(payloadJson)
                    .previousHash(previousHash)
                    .selfHash(selfHash)
                    .sequenceNumber(sequenceNumber)
                    .build();

            return repository.save(entry);

        } catch (Exception e) {
            log.error("AuditChain: falha ao persistir entry actor={} eventType={}: {}",
                    actor, eventType, e.getMessage());
            return null;
        }
    }

    private String serializePayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            log.warn("AuditChain: falha ao serializar payload, usando fallback: {}", e.getMessage());
            return "{\"error\":\"payload_serialization_failed\"}";
        }
    }
}
