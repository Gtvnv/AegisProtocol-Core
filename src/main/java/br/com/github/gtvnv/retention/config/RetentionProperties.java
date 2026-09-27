package br.com.github.gtvnv.retention.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Satélite Retention Engine (ISO A.8.10). NÃO apaga entries do Ômega — o
 * hardening WORM (docs/worm-hardening.sql) revoga UPDATE/DELETE do usuário
 * da aplicação de propósito, e um DELETE no meio da cadeia quebraria o
 * previousHash de tudo que vem depois. O que este satélite faz é arquivar
 * (exportar + checkpoint assinado) entries fora da janela de retenção,
 * deixando o purge físico — se um dia for legalmente exigido — como
 * operação manual de superuser/DBA, igual o resto do hardening WORM já
 * assume.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.retention")
public class RetentionProperties {
    private boolean enabled = true;
    private int chainRetentionDays = 365;
    private String archiveDir = "audit-archive";
    private int batchSize = 500;
    private String cron = "0 0 2 * * *"; // 02:00 todo dia
}
