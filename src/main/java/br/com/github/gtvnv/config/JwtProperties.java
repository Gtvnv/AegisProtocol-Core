package br.com.github.gtvnv.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.jwt")
public class JwtProperties {
    private String privateKeyPath;
    private String publicKeyPath;
    private long accessTokenExpiration;  // segundos
    private long refreshTokenExpiration; // segundos

    // Satélite KMS/Secrets: rotação de chave RS256 sem downtime.
    // Quantas chaves ficam válidas para VERIFICAÇÃO (atual + anteriores). Assinatura de
    // tokens novos usa sempre só a atual. Deve cobrir pelo menos a vida do refresh token.
    private int keyRetentionCount = 3;
    // Diretório onde as chaves públicas anteriores são arquivadas. Vazio = pasta
    // "archive" ao lado do arquivo de chave privada configurado acima.
    private String keyArchiveDir;
}