package br.com.github.gtvnv.shield.event;

import br.com.github.gtvnv.shield.service.ShieldRiskScorer.ScoreResult;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class ShieldThreatEvent extends ApplicationEvent {

    private final String actor;
    private final String jti;
    private final String ipAddress;
    private final String userAgent;
    private final String resourcePath;
    private final ScoreResult scoreResult;
    private final boolean blocked;

    public ShieldThreatEvent(Object source, String actor, String jti,
                             String ipAddress, String userAgent,
                             String resourcePath, ScoreResult scoreResult,
                             boolean blocked) {
        super(source);
        this.actor        = actor;
        this.jti          = jti;
        this.ipAddress    = ipAddress;
        this.userAgent    = userAgent;
        this.resourcePath = resourcePath;
        this.scoreResult  = scoreResult;
        this.blocked      = blocked;
    }
}
