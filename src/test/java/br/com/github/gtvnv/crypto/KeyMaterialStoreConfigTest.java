package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.crypto.vault.VaultKeyMaterialStore;
import br.com.github.gtvnv.crypto.vault.VaultProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Garante que exatamente UM KeyMaterialStore sobe, e o certo, conforme
 * aegis.jwt.key-source — sem precisar da aplicação inteira (sem banco, sem
 * Redis, sem Vault real). Existe porque nenhum outro teste hoje sobe o
 * contexto Spring completo o bastante pra pegar um conflito de bean aqui.
 */
class KeyMaterialStoreConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations.of(
                    RestTemplateAutoConfiguration.class))
            .withUserConfiguration(KeyMaterialStoreConfig.class)
            .withBean(JwtProperties.class)
            .withBean(VaultProperties.class);

    @Test
    @DisplayName("Sem aegis.jwt.key-source definido, sobe FileKeyMaterialStore (matchIfMissing)")
    void noKeySourceConfigured_DefaultsToFile() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(KeyMaterialStore.class);
            assertThat(context.getBean(KeyMaterialStore.class)).isInstanceOf(FileKeyMaterialStore.class);
        });
    }

    @Test
    @DisplayName("aegis.jwt.key-source=file sobe FileKeyMaterialStore")
    void keySourceFile_UsesFileStore() {
        runner.withPropertyValues("aegis.jwt.key-source=file").run(context -> {
            assertThat(context).hasSingleBean(KeyMaterialStore.class);
            assertThat(context.getBean(KeyMaterialStore.class)).isInstanceOf(FileKeyMaterialStore.class);
        });
    }

    @Test
    @DisplayName("aegis.jwt.key-source=vault sobe VaultKeyMaterialStore, não o de arquivo")
    void keySourceVault_UsesVaultStore() {
        runner.withPropertyValues("aegis.jwt.key-source=vault").run(context -> {
            assertThat(context).hasSingleBean(KeyMaterialStore.class);
            assertThat(context.getBean(KeyMaterialStore.class)).isInstanceOf(VaultKeyMaterialStore.class);
        });
    }
}
