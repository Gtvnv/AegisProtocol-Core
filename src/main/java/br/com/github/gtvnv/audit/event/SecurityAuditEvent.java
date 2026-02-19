package br.com.github.gtvnv.audit.event;

import br.com.github.gtvnv.domain.model.AccessContext;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class SecurityAuditEvent extends ApplicationEvent {

    private final AccessContext context;
    private final boolean allowed;
    private final String reason;

    public SecurityAuditEvent(Object source, AccessContext context, boolean allowed, String reason) {
        super(source);
        this.context = context;
        this.allowed = allowed;
        this.reason = reason;
    }
}