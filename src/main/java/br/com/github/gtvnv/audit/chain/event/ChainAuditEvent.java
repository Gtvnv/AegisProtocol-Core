package br.com.github.gtvnv.audit.chain.event;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.Map;

@Getter
public class ChainAuditEvent extends ApplicationEvent {

    private final AuditEventType eventType;
    private final String actor;
    private final String sessionJti;
    private final String ipAddress;
    private final String userAgent;
    private final String resourcePath;
    private final String detail;
    private final Map<String, Object> payload;

    public ChainAuditEvent(Object source,
                           AuditEventType eventType,
                           String actor,
                           String sessionJti,
                           String ipAddress,
                           String userAgent,
                           String resourcePath,
                           String detail,
                           Map<String, Object> payload) {
        super(source);
        this.eventType    = eventType;
        this.actor        = actor != null ? actor : "ANONYMOUS";
        this.sessionJti   = sessionJti;
        this.ipAddress    = ipAddress;
        this.userAgent    = userAgent;
        this.resourcePath = resourcePath;
        this.detail       = detail;
        this.payload      = payload != null ? payload : Map.of();
    }
}
