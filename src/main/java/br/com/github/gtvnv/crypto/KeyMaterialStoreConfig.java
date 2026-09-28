package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.crypto.vault.VaultKeyMaterialStore;
import br.com.github.gtvnv.crypto.vault.VaultProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * Escolhe qual KeyMaterialStore fica de pé, via aegis.jwt.key-source.
 * Exatamente um dos dois beans é criado — KeyManagerService depende só da
 * interface, então não sabe (nem precisa saber) qual venceu.
 */
@Configuration
public class KeyMaterialStoreConfig {

    @Bean
    @ConditionalOnProperty(prefix = "aegis.jwt", name = "key-source", havingValue = "file", matchIfMissing = true)
    public KeyMaterialStore fileKeyMaterialStore(JwtProperties jwtProperties) {
        return new FileKeyMaterialStore(jwtProperties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "aegis.jwt", name = "key-source", havingValue = "vault")
    public KeyMaterialStore vaultKeyMaterialStore(VaultProperties vaultProperties, RestTemplateBuilder builder) {
        RestTemplate restTemplate = builder
                .connectTimeout(Duration.ofMillis(vaultProperties.getConnectTimeoutMs()))
                .readTimeout(Duration.ofMillis(vaultProperties.getReadTimeoutMs()))
                .build();
        return new VaultKeyMaterialStore(vaultProperties, restTemplate);
    }
}
