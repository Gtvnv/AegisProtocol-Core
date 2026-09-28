package br.com.github.gtvnv.crypto.vault;

import br.com.github.gtvnv.crypto.KeyGeneratorUtils;
import br.com.github.gtvnv.crypto.KeyMaterialStore;
import br.com.github.gtvnv.crypto.PemUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * Satélite KMS/Vault real — VaultKeyMaterialStore fala HTTP puro com a API
 * KV v2 do Vault. Sem um Vault de verdade neste ambiente (sem Docker
 * disponível) — MockRestServiceServer valida a conversa (URLs, verbo,
 * header X-Vault-Token, corpo) sem precisar de um servidor real.
 */
class VaultKeyMaterialStoreTest {

    private static final String ADDRESS = "http://127.0.0.1:8200";
    private static final String MOUNT = "secret";
    private static final String BASE_PATH = "aegis/jwt";
    private static final String TOKEN = "test-token";

    private RestTemplate restTemplate;
    private MockRestServiceServer server;
    private VaultKeyMaterialStore store;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();

        VaultProperties properties = new VaultProperties();
        properties.setAddress(ADDRESS);
        properties.setMount(MOUNT);
        properties.setBasePath(BASE_PATH);
        properties.setToken(TOKEN);

        store = new VaultKeyMaterialStore(properties, restTemplate);
    }

    private String dataUrl(String path) {
        return ADDRESS + "/v1/" + MOUNT + "/data/" + BASE_PATH + "/" + path;
    }

    private String metadataUrl(String path) {
        return ADDRESS + "/v1/" + MOUNT + "/metadata/" + BASE_PATH + "/" + path;
    }

    // -----------------------------------------------------------------------
    // loadCurrent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("loadCurrent() lê o par de current, decodifica e marca como gravável")
    void loadCurrent_ReadsAndDecodesKeyPair() throws Exception {
        KeyPair pair = KeyGeneratorUtils.generateRsaKey();
        String privPem = PemUtils.encode(pair.getPrivate().getEncoded(), "PRIVATE");
        String pubPem = PemUtils.encode(pair.getPublic().getEncoded(), "PUBLIC");

        server.expect(requestTo(dataUrl("current")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("X-Vault-Token", TOKEN))
                .andRespond(withSuccess("""
                        {"data":{"data":{"private_key_pem":%s,"public_key_pem":%s},"metadata":{"version":1}}}
                        """.formatted(jsonString(privPem), jsonString(pubPem)), MediaType.APPLICATION_JSON));

        KeyMaterialStore.LoadedKeyMaterial loaded = store.loadCurrent();

        assertThat(loaded.writable()).isTrue();
        assertThat(loaded.publicKey().getEncoded()).isEqualTo(pair.getPublic().getEncoded());
        assertThat(loaded.privateKey().getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
        server.verify();
    }

    @Test
    @DisplayName("loadCurrent() sem chave inicial no Vault (404) lança IOException explicativa")
    void loadCurrent_NotFound_ThrowsIOException() {
        server.expect(requestTo(dataUrl("current")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withResourceNotFound());

        assertThatThrownBy(() -> store.loadCurrent())
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("current");
    }

    // -----------------------------------------------------------------------
    // writeCurrent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("writeCurrent() envia PEM de ambas as chaves pro path 'current'")
    void writeCurrent_PostsBothPems() throws Exception {
        KeyPair pair = KeyGeneratorUtils.generateRsaKey();

        server.expect(requestTo(dataUrl("current")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Vault-Token", TOKEN))
                .andExpect(content().string(containsString("private_key_pem")))
                .andExpect(content().string(containsString("public_key_pem")))
                .andRespond(withSuccess("{\"data\":{\"version\":2}}", MediaType.APPLICATION_JSON));

        store.writeCurrent((java.security.interfaces.RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());

        server.verify();
    }

    // -----------------------------------------------------------------------
    // archivePublicKey — não-destrutivo
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("archivePublicKey() escreve quando o kid ainda não está arquivado")
    void archivePublicKey_NotYetArchived_Writes() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) KeyGeneratorUtils.generateRsaKey().getPublic();

        server.expect(requestTo(dataUrl("archive/kid1")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withResourceNotFound());
        server.expect(requestTo(dataUrl("archive/kid1")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("public_key_pem")))
                .andRespond(withSuccess("{\"data\":{\"version\":1}}", MediaType.APPLICATION_JSON));

        store.archivePublicKey("kid1", publicKey);

        server.verify();
    }

    @Test
    @DisplayName("archivePublicKey() não escreve de novo quando o kid já está arquivado")
    void archivePublicKey_AlreadyArchived_DoesNotWrite() throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) KeyGeneratorUtils.generateRsaKey().getPublic();
        String pubPem = PemUtils.encode(publicKey.getEncoded(), "PUBLIC");

        server.expect(requestTo(dataUrl("archive/kid1")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {"data":{"data":{"public_key_pem":%s},"metadata":{"version":1}}}
                        """.formatted(jsonString(pubPem)), MediaType.APPLICATION_JSON));
        // Nenhum outro expect: se o store tentar um segundo request (POST), server.verify() falha.

        store.archivePublicKey("kid1", publicKey);

        server.verify();
    }

    // -----------------------------------------------------------------------
    // loadArchivedPublicKey
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("loadArchivedPublicKey() de um kid inexistente retorna Optional vazio")
    void loadArchivedPublicKey_NotFound_ReturnsEmpty() throws Exception {
        server.expect(requestTo(dataUrl("archive/ghost")))
                .andRespond(withResourceNotFound());

        Optional<RSAPublicKey> result = store.loadArchivedPublicKey("ghost");

        assertThat(result).isEmpty();
    }

    // -----------------------------------------------------------------------
    // archive-history
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("loadArchiveHistory() sem histórico ainda (404) retorna lista vazia")
    void loadArchiveHistory_NotFound_ReturnsEmptyList() throws Exception {
        server.expect(requestTo(dataUrl("archive-history")))
                .andRespond(withResourceNotFound());

        assertThat(store.loadArchiveHistory()).isEmpty();
    }

    @Test
    @DisplayName("loadArchiveHistory() parseia a lista de kids separada por vírgula")
    void loadArchiveHistory_ParsesCommaSeparatedKids() throws Exception {
        server.expect(requestTo(dataUrl("archive-history")))
                .andRespond(withSuccess("""
                        {"data":{"data":{"kids":"kid1,kid2,kid3"},"metadata":{"version":3}}}
                        """, MediaType.APPLICATION_JSON));

        assertThat(store.loadArchiveHistory()).containsExactly("kid1", "kid2", "kid3");
    }

    @Test
    @DisplayName("appendArchiveHistory() lê o histórico existente e grava com o novo kid no final")
    void appendArchiveHistory_ReadsThenWritesUpdatedList() throws Exception {
        server.expect(requestTo(dataUrl("archive-history")))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {"data":{"data":{"kids":"kid1,kid2"},"metadata":{"version":1}}}
                        """, MediaType.APPLICATION_JSON));
        server.expect(requestTo(dataUrl("archive-history")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("kid1,kid2,kid3")))
                .andRespond(withSuccess("{\"data\":{\"version\":2}}", MediaType.APPLICATION_JSON));

        store.appendArchiveHistory("kid3");

        server.verify();
    }

    // -----------------------------------------------------------------------
    // deleteArchivedKey
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("deleteArchivedKey() manda DELETE na metadata (destrói todas as versões)")
    void deleteArchivedKey_DeletesMetadata() throws Exception {
        server.expect(requestTo(metadataUrl("archive/kid1")))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header("X-Vault-Token", TOKEN))
                .andRespond(withNoContent());

        store.deleteArchivedKey("kid1");

        server.verify();
    }

    @Test
    @DisplayName("deleteArchivedKey() de algo que já não existe (404) não lança")
    void deleteArchivedKey_AlreadyGone_DoesNotThrow() {
        server.expect(requestTo(metadataUrl("archive/ghost")))
                .andExpect(method(HttpMethod.DELETE))
                .andRespond(withResourceNotFound());

        assertThatCode(() -> store.deleteArchivedKey("ghost")).doesNotThrowAnyException();
    }

    // --- helpers ---

    /** Serializa uma String Java como literal JSON (escapa quebras de linha do PEM etc). */
    private String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
