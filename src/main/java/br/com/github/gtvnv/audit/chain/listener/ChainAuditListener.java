package br.com.github.gtvnv.audit.chain.listener;

import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import br.com.github.gtvnv.privacy.service.PrivacyGateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Consome ChainAuditEvent de forma assíncrona e delega para AuditChainService.
 * REQUIRES_NEW garante persistência independente da transação chamadora —
 * o entry é gravado mesmo que a transação original faça rollback.
 *
 * Também é o PrivacyGate: última parada antes da escrita imutável no Ômega,
 * onde o 'actor' é trocado pelo pseudônimo do titular (ver PrivacyGateService).
 * Eventos de categoria THREAT usam IP como actor, não uma identidade — passam
 * direto. Qualquer categoria nova entra pseudonimizada por padrão (fail-safe
 * a favor da privacidade); quem precisar do texto puro pede exceção aqui.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ChainAuditListener {

    private static final String THREAT_CATEGORY = "THREAT";
    private static final String ANONYMOUS_ACTOR = "ANONYMOUS";

    private final AuditChainService chainService;
    private final PrivacyGateService privacyGate;

    @Async
    @EventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onChainAuditEvent(ChainAuditEvent event) {
        try {
            chainService.append(
                    event.getEventType(),
                    resolveActor(event),
                    event.getSessionJti(),
                    event.getIpAddress(),
                    event.getUserAgent(),
                    event.getResourcePath(),
                    event.getDetail(),
                    event.getPayload()
            );
        } catch (Exception e) {
            log.error("ChainAuditListener: falha ao processar evento actor={} type={}: {}",
                    event.getActor(), event.getEventType(), e.getMessage());
        }
    }

    private String resolveActor(ChainAuditEvent event) {
        String actor = event.getActor();
        if (ANONYMOUS_ACTOR.equals(actor)) {
            return actor;
        }
        Object category = event.getPayload().get("eventCategory");
        if (THREAT_CATEGORY.equals(category)) {
            return actor; // IP, não identidade — nada a pseudonimizar
        }
        return privacyGate.pseudonymize(actor);
    }
}
