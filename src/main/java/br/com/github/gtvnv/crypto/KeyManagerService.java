package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Gerencia o par de chaves RSA usado para assinar/validar os JWTs — e a rotação delas.
 *
 * Satélite "KMS/Secrets" do roadmap de compliance (fecha ISO 27001 A.8.24 parcialmente):
 * a chave privada deixou de ser estática — cada rotação gera um novo par, mantém as
 * chaves públicas anteriores verificáveis por um "kid" (key id) e permite revogar a
 * chave antiga sem invalidar tokens ainda válidos emitidos com ela (rotação sem downtime).
 *
 * Persistência: delegada a um KeyMaterialStore (satélite "KMS/Vault real" — ver
 * aegis.jwt.key-source). Esta classe só cuida de kid, keyring em memória e orquestração
 * da rotação — nenhuma linha aqui sabe se a chave mora em arquivo ou no Vault.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeyManagerService {

    private final JwtProperties jwtProperties;
    private final KeyMaterialStore store;

    /** Chaves públicas válidas para verificação, indexadas por kid (atual + histórico dentro da retenção). */
    private final Map<String, RSAPublicKey> publicKeysByKid = new ConcurrentHashMap<>();
    /** kids anteriores ao atual, do mais antigo para o mais novo (o atual NÃO entra aqui). */
    private final List<String> previousKids = new CopyOnWriteArrayList<>();

    @Getter
    private volatile String currentKid;
    private volatile RSAPrivateKey currentPrivateKey;
    private volatile boolean writable;

    public record RotationResult(String previousKid, String newKid, List<String> retainedKids) {}

    @PostConstruct
    public void loadKeys() {
        try {
            log.info("🔐 KeyManager: Carregando par de chaves RSA...");

            KeyMaterialStore.LoadedKeyMaterial loaded = store.loadCurrent();
            this.writable = loaded.writable();
            this.currentPrivateKey = loaded.privateKey();
            this.currentKid = computeKid(loaded.publicKey());
            this.publicKeysByKid.put(currentKid, loaded.publicKey());

            if (writable) {
                loadArchivedKeys();
            } else {
                log.warn("⚠️ KeyManager: chaves carregadas de uma fonte somente-leitura — rotação indisponível.");
            }

            log.info("✅ KeyManager: Chaves carregadas com sucesso! kid atual={} (+{} chave(s) anterior(es) verificável(is))",
                    currentKid, previousKids.size());
        } catch (Exception e) {
            log.error("❌ KeyManager: Falha crítica ao carregar chaves.", e);
            throw new RuntimeException("Falha na inicialização criptográfica", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        return publicKeysByKid.get(currentKid);
    }

    public RSAPrivateKey getPrivateKey() {
        return currentPrivateKey;
    }

    /** Todas as chaves públicas ainda válidas para verificação (atual + histórico dentro da retenção), por kid. */
    public Map<String, RSAPublicKey> getVerificationKeys() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(publicKeysByKid));
    }

    /**
     * Resolve a chave pública para verificar um token pelo seu 'kid'.
     * Um token sem 'kid' (emitido antes desta feature existir) é tratado como assinado
     * pela chave atual, para não invalidar sessões antigas na primeira subida.
     */
    public RSAPublicKey getVerificationKey(String kid) {
        if (kid == null) {
            return getPublicKey();
        }
        RSAPublicKey key = publicKeysByKid.get(kid);
        if (key == null) {
            throw new SignatureException("Chave de assinatura desconhecida ou expirada (kid=" + kid + ")");
        }
        return key;
    }

    /**
     * Gera um novo par RSA, arquiva a chave pública atual (continua válida para
     * verificação até sair da janela de retenção) e passa a assinar com a nova.
     * Indisponível quando o KeyMaterialStore é somente-leitura.
     */
    public synchronized RotationResult rotate() {
        if (!writable) {
            throw new IllegalStateException("Rotação indisponível: fonte de chaves não é gravável.");
        }

        String outgoingKid = this.currentKid;
        try {
            store.archivePublicKey(outgoingKid, publicKeysByKid.get(outgoingKid));

            KeyPair newPair = KeyGeneratorUtils.generateRsaKey();
            RSAPublicKey newPublicKey = (RSAPublicKey) newPair.getPublic();
            RSAPrivateKey newPrivateKey = (RSAPrivateKey) newPair.getPrivate();
            String newKid = computeKid(newPublicKey);

            store.writeCurrent(newPrivateKey, newPublicKey);

            publicKeysByKid.put(newKid, newPublicKey);
            previousKids.add(outgoingKid);
            store.appendArchiveHistory(outgoingKid);

            this.currentPrivateKey = newPrivateKey;
            this.currentKid = newKid;

            List<String> pruned = enforceRetention();

            log.warn("🔄 KeyManager: chave rotacionada. anterior={} nova={} retidas={} removidas={}",
                    outgoingKid, newKid, previousKids, pruned);

            return new RotationResult(outgoingKid, newKid, List.copyOf(previousKids));
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao rotacionar chaves RSA", e);
        }
    }

    // --- Carregamento ---

    private void loadArchivedKeys() {
        try {
            List<String> history = store.loadArchiveHistory();
            for (String kid : history) {
                if (kid.equals(currentKid)) {
                    continue;
                }
                store.loadArchivedPublicKey(kid).ifPresent(publicKey -> {
                    publicKeysByKid.put(kid, publicKey);
                    previousKids.add(kid);
                });
            }
        } catch (Exception e) {
            log.warn("⚠️ KeyManager: falha ao carregar chaves arquivadas, seguindo só com a atual.", e);
        }
    }

    /** Mantém só as últimas N chaves (atual + N-1 anteriores); descarta o resto do keyring e da fonte. */
    private List<String> enforceRetention() {
        int retention = Math.max(1, jwtProperties.getKeyRetentionCount());
        List<String> removed = new ArrayList<>();
        while (previousKids.size() > retention - 1) {
            String oldest = previousKids.remove(0);
            publicKeysByKid.remove(oldest);
            removed.add(oldest);
            try {
                store.deleteArchivedKey(oldest);
            } catch (IOException e) {
                log.warn("⚠️ KeyManager: não consegui remover chave arquivada expirada kid={}", oldest, e);
            }
        }
        if (!removed.isEmpty()) {
            log.info("🧹 KeyManager: chaves fora da janela de retenção removidas: {}", removed);
        }
        return removed;
    }

    /** kid determinístico = thumbprint SHA-256 da chave pública (16 chars hex) — sem depender de estado externo. */
    private String computeKid(RSAPublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }
}
