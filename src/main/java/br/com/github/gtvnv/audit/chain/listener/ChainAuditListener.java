package br.com.github.gtvnv.audit.chain.listener;

import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
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
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ChainAuditListener {

    private final AuditChainService chainService;

    @Async
    @EventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onChainAuditEvent(ChainAuditEvent event) {
        try {
            chainService.append(
                    event.getEventType(),
                    event.getActor(),
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
}
