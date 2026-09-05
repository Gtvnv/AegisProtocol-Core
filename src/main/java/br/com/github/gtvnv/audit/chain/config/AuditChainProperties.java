package br.com.github.gtvnv.audit.chain.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "aegis.audit.chain")
public class AuditChainProperties {

    private boolean enabled = true;
    private boolean verifyOnStartup = false;
    private int maxPayloadSizeBytes = 4096;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isVerifyOnStartup() { return verifyOnStartup; }
    public void setVerifyOnStartup(boolean verifyOnStartup) { this.verifyOnStartup = verifyOnStartup; }

    public int getMaxPayloadSizeBytes() { return maxPayloadSizeBytes; }
    public void setMaxPayloadSizeBytes(int maxPayloadSizeBytes) { this.maxPayloadSizeBytes = maxPayloadSizeBytes; }
}
