package br.com.github.gtvnv.crypto.vault;

import br.com.github.gtvnv.crypto.KeyMaterialStore;
import br.com.github.gtvnv.crypto.PemUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * KeyMaterialStore satélite KMS/Vault real (aegis.jwt.key-source=vault) —
 * o par de chaves e o histórico de rotação vivem no HashiCorp Vault (KV v2),
 * não em arquivo local. Ativa via docker-compose (serviço `aegis-vault`,
 * dev mode) ou um Vault já existente na sua infra.
 *
 * Isolamento intencional: este store só troca ONDE o material fica — kid,
 * keyring em memória e orquestração da rotação continuam 100% em
 * KeyManagerService, sem saber que a fonte mudou.
 *
 * Ressalva documentada (ver Roadmap 2 do mapeamento de compliance): isto é
 * Vault como COFRE de chave — a chave privada ainda sai do Vault e assina
 * localmente via JJWT, igual ao FileKeyMaterialStore. Delegar a assinatura
 * em si pro Vault Transit engine (chave privada NUNCA sai do Vault) é um
 * passo mais forte, ainda não implementado aqui.
 */
@RequiredArgsConstructor
public class VaultKeyMaterialStore implements KeyMaterialStore {

    private static final String CURRENT_PATH = "current";
    private static final String HISTORY_PATH = "archive-history";
    private static final String ARCHIVE_PREFIX = "archive/";

    private final VaultProperties properties;
    private final RestTemplate restTemplate;

    @Override
    public LoadedKeyMaterial loadCurrent() throws IOException {
        Map<String, String> data = readSecret(CURRENT_PATH)
                .orElseThrow(() -> new IOException(
                        "Nenhuma chave 'current' encontrada no Vault em " + fullPath(CURRENT_PATH)
                                + " — grave o par inicial lá antes de subir com aegis.jwt.key-source=vault."));

        RSAPrivateKey privateKey = PemUtils.decodePrivateKey(PemUtils.sanitize(data.get("private_key_pem"), "PRIVATE"));
        RSAPublicKey publicKey = PemUtils.decodePublicKey(PemUtils.sanitize(data.get("public_key_pem"), "PUBLIC"));
        // Vault é sempre gravável do ponto de vista deste store — uma falha de
        // permissão do token aparece como erro na escrita, não aqui.
        return new LoadedKeyMaterial(privateKey, publicKey, true);
    }

    @Override
    public void writeCurrent(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws IOException {
        writeSecret(CURRENT_PATH, Map.of(
                "private_key_pem", PemUtils.encode(privateKey.getEncoded(), "PRIVATE"),
                "public_key_pem", PemUtils.encode(publicKey.getEncoded(), "PUBLIC")
        ));
    }

    @Override
    public void archivePublicKey(String kid, RSAPublicKey publicKey) throws IOException {
        if (readSecret(ARCHIVE_PREFIX + kid).isPresent()) {
            return; // não-destrutivo — já arquivada
        }
        writeSecret(ARCHIVE_PREFIX + kid, Map.of("public_key_pem", PemUtils.encode(publicKey.getEncoded(), "PUBLIC")));
    }

    @Override
    public Optional<RSAPublicKey> loadArchivedPublicKey(String kid) throws IOException {
        Optional<Map<String, String>> data = readSecret(ARCHIVE_PREFIX + kid);
        if (data.isEmpty()) {
            return Optional.empty();
        }
        String pem = data.get().get("public_key_pem");
        return Optional.of(PemUtils.decodePublicKey(PemUtils.sanitize(pem, "PUBLIC")));
    }

    @Override
    public List<String> loadArchiveHistory() throws IOException {
        return readSecret(HISTORY_PATH)
                .map(data -> data.get("kids"))
                .filter(kids -> kids != null && !kids.isBlank())
                .map(kids -> List.of(kids.split(",")))
                .orElseGet(List::of);
    }

    @Override
    public void appendArchiveHistory(String kid) throws IOException {
        List<String> updated = new ArrayList<>(loadArchiveHistory());
        updated.add(kid);
        writeSecret(HISTORY_PATH, Map.of("kids", String.join(",", updated)));
    }

    @Override
    public void deleteArchivedKey(String kid) throws IOException {
        deleteSecretPermanently(ARCHIVE_PREFIX + kid);
    }

    // --- Vault KV v2 HTTP ---

    @SuppressWarnings("unchecked")
    private Optional<Map<String, String>> readSecret(String path) throws IOException {
        try {
            var response = restTemplate.exchange(dataUrl(path), HttpMethod.GET, authEntity(), Map.class);
            Map<String, Object> body = response.getBody();
            if (body == null) {
                return Optional.empty();
            }
            Map<String, Object> outer = (Map<String, Object>) body.get("data");
            if (outer == null) {
                return Optional.empty();
            }
            Map<String, String> inner = (Map<String, String>) outer.get("data");
            return Optional.ofNullable(inner);
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (RestClientException e) {
            throw new IOException("Falha ao ler do Vault: " + fullPath(path), e);
        }
    }

    private void writeSecret(String path, Map<String, String> data) throws IOException {
        try {
            HttpHeaders headers = authHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(Map.of("data", data), headers);
            restTemplate.postForEntity(dataUrl(path), entity, Map.class);
        } catch (RestClientException e) {
            throw new IOException("Falha ao escrever no Vault: " + fullPath(path), e);
        }
    }

    /** DELETE na metadata (não no data) = destrói TODAS as versões — equivalente a Files.deleteIfExists. */
    private void deleteSecretPermanently(String path) throws IOException {
        try {
            restTemplate.exchange(metadataUrl(path), HttpMethod.DELETE, authEntity(), Void.class);
        } catch (HttpClientErrorException.NotFound e) {
            // já não existia — mesma semântica de deleteIfExists, sucesso silencioso
        } catch (RestClientException e) {
            throw new IOException("Falha ao apagar do Vault: " + fullPath(path), e);
        }
    }

    private String dataUrl(String path) {
        return properties.getAddress() + "/v1/" + properties.getMount() + "/data/" + fullPath(path);
    }

    private String metadataUrl(String path) {
        return properties.getAddress() + "/v1/" + properties.getMount() + "/metadata/" + fullPath(path);
    }

    private String fullPath(String path) {
        return properties.getBasePath() + "/" + path;
    }

    private HttpHeaders authHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Vault-Token", properties.getToken());
        return headers;
    }

    private HttpEntity<Void> authEntity() {
        return new HttpEntity<>(authHeaders());
    }
}
