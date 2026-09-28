package br.com.github.gtvnv.crypto.vault;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Satélite KMS/Vault real: onde falar com o HashiCorp Vault pra guardar o
 * par de chaves RS256, no lugar do arquivo local (FileKeyMaterialStore).
 * Só entra em uso quando aegis.jwt.key-source=vault.
 *
 * O token normalmente NÃO deve vir do application.yml em produção — use
 * ${AEGIS_VAULT_TOKEN} (variável de ambiente) ou um AppRole; o campo aqui
 * existe pra permitir isso via placeholder, não pra hardcodar o token.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.vault")
public class VaultProperties {
    private String address = "http://127.0.0.1:8200";
    private String token;
    private String mount = "secret";       // mount da KV v2 engine
    private String basePath = "aegis/jwt"; // prefixo dos caminhos dentro do mount
    private int connectTimeoutMs = 3000;
    private int readTimeoutMs = 3000;
}
