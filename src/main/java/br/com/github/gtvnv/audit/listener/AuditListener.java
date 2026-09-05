package br.com.github.gtvnv.audit.listener;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.audit.domain.AuditLog;
import br.com.github.gtvnv.audit.event.SecurityAuditEvent;
import br.com.github.gtvnv.audit.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditListener {

    private final AuditLogRepository repository;
    private final AuditEventPublisher chainPublisher;

    @Async // Executa em thread separada (Assíncrono)
    @EventListener // Escuta o evento disparado pelo Interceptor
    @Transactional(propagation = Propagation.REQUIRES_NEW) // Garante transação nova e independente
    public void onSecurityEvent(SecurityAuditEvent event) {
        try {
            var context = event.getContext();

            // Log de entrada para confirmar que o evento chegou aqui
            log.info("📨 Processando evento de auditoria para: {}", context.resource().identifier());

            AuditLog auditLog = AuditLog.builder()
                    .timestamp(LocalDateTime.ofInstant(context.environment().timestamp(), ZoneId.systemDefault()))
                    .actor(context.subject().id())
                    .action(context.action())
                    .resource(context.resource().identifier())
                    .ipAddress(context.environment().ipAddress())
                    .outcome(event.isAllowed() ? "ALLOWED" : "DENIED")
                    .detail(event.getReason())
                    .build();

            // 🔥 ALTERAÇÃO 1: saveAndFlush
            // Força o insert no banco IMEDIATAMENTE. Se houver erro de SQL, estoura aqui e cai no catch.
            repository.saveAndFlush(auditLog);
            log.info("✅ Audit Log salvo com sucesso ID: {}", auditLog.getId());

            AuditEventType chainType = event.isAllowed()
                    ? AuditEventType.ABAC_DECISION_PERMIT
                    : AuditEventType.ABAC_DECISION_DENY;
            chainPublisher.publishAbacEvent(chainType,
                    context.subject().id(),
                    context.resource().identifier(),
                    context.action(),
                    event.getReason());

        } catch (Exception e) {
            // Agora sim veremos o erro real se o banco rejeitar o dado
            log.error("❌ Falha crítica ao salvar Audit Log: {}", e.getMessage(), e);
        }
    }
}