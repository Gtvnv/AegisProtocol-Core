package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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
 * ainda não há Vault/HSM externo, mas a chave privada deixou de ser estática — cada
 * rotação gera um novo par, mantém as chaves públicas anteriores verificáveis por um
 * "kid" (key id) e permite revogar a chave antiga sem invalidar tokens ainda válidos
 * emitidos com ela (rotação sem downtime).
 *
 * Persistência: os pares continuam em arquivo (mesma pasta configurada em
 * aegis.jwt.*-key-path) — a troca por um provider de KMS/Vault real fica para uma
 * evolução futura, mas a API pública (getPrivateKey/getVerificationKey/rotate) já
 * não depende de como a chave é armazenada.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeyManagerService {

    private static final String ARCHIVE_HISTORY_FILE = "history.txt";
    private static final int PEM_LINE_LENGTH = 64;

    private final JwtProperties jwtProperties;

    /** Chaves públicas válidas para verificação, indexadas por kid (atual + histórico dentro da retenção). */
    private final Map<String, RSAPublicKey> publicKeysByKid = new ConcurrentHashMap<>();
    /** kids anteriores ao atual, do mais antigo para o mais novo (o atual NÃO entra aqui). */
    private final List<String> previousKids = new CopyOnWriteArrayList<>();

    @Getter
    private volatile String currentKid;
    private volatile RSAPrivateKey currentPrivateKey;

    private volatile boolean filesystemBacked;
    private volatile Path privateKeyFile;
    private volatile Path publicKeyFile;
    private volatile Path archiveDir;

    public record RotationResult(String previousKid, String newKid, List<String> retainedKids) {}

    @PostConstruct
    public void loadKeys() {
        try {
            log.info("🔐 KeyManager: Carregando par de chaves RSA...");

            LoadedKey publicLoaded = loadKey(jwtProperties.getPublicKeyPath(), "PUBLIC");
            RSAPublicKey publicKey = decodePublicKey(publicLoaded.content());

            LoadedKey privateLoaded = loadKey(jwtProperties.getPrivateKeyPath(), "PRIVATE");
            RSAPrivateKey privateKey = decodePrivateKey(privateLoaded.content());

            this.filesystemBacked = privateLoaded.fromFilesystem() && publicLoaded.fromFilesystem();
            this.privateKeyFile = privateLoaded.path();
            this.publicKeyFile = publicLoaded.path();
            this.archiveDir = filesystemBacked ? resolveArchiveDir(privateLoaded.path()) : null;

            this.currentKid = computeKid(publicKey);
            this.currentPrivateKey = privateKey;
            this.publicKeysByKid.put(currentKid, publicKey);

            if (filesystemBacked) {
                loadArchivedKeys();
            } else {
                log.warn("⚠️ KeyManager: chaves carregadas do classpath (somente leitura) — rotação indisponível.");
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
     * Indisponível quando as chaves vieram do classpath (somente leitura).
     */
    public synchronized RotationResult rotate() {
        if (!filesystemBacked) {
            throw new IllegalStateException("Rotação indisponível: chaves não estão em um diretório gravável.");
        }

        String outgoingKid = this.currentKid;
        try {
            Files.createDirectories(archiveDir);
            archivePublicKey(outgoingKid, publicKeysByKid.get(outgoingKid));

            KeyPair newPair = KeyGeneratorUtils.generateRsaKey();
            RSAPublicKey newPublicKey = (RSAPublicKey) newPair.getPublic();
            RSAPrivateKey newPrivateKey = (RSAPrivateKey) newPair.getPrivate();
            String newKid = computeKid(newPublicKey);

            writePem(privateKeyFile, "PRIVATE", newPrivateKey.getEncoded());
            writePem(publicKeyFile, "PUBLIC", newPublicKey.getEncoded());

            publicKeysByKid.put(newKid, newPublicKey);
            previousKids.add(outgoingKid);
            appendArchiveHistory(outgoingKid);

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

    private record LoadedKey(String content, Path path, boolean fromFilesystem) {}

    private LoadedKey loadKey(String path, String type) throws IOException {
        FileSystemResource fsResource = new FileSystemResource(path);
        if (fsResource.exists()) {
            String content = StreamUtils.copyToString(fsResource.getInputStream(), StandardCharsets.UTF_8);
            return new LoadedKey(sanitizeKey(content, type), fsResource.getFile().toPath(), true);
        }
        ClassPathResource cpResource = new ClassPathResource(path);
        String content = StreamUtils.copyToString(cpResource.getInputStream(), StandardCharsets.UTF_8);
        return new LoadedKey(sanitizeKey(content, type), null, false);
    }

    private void loadArchivedKeys() {
        try {
            if (!Files.isDirectory(archiveDir)) {
                return;
            }
            Path historyFile = archiveDir.resolve(ARCHIVE_HISTORY_FILE);
            if (!Files.exists(historyFile)) {
                return;
            }
            List<String> history = Files.readAllLines(historyFile, StandardCharsets.UTF_8).stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .toList();

            for (String kid : history) {
                Path archivedFile = archiveDir.resolve(kid + ".pub.pem");
                if (!Files.exists(archivedFile) || kid.equals(currentKid)) {
                    continue;
                }
                String content = sanitizeKey(Files.readString(archivedFile, StandardCharsets.UTF_8), "PUBLIC");
                publicKeysByKid.put(kid, decodePublicKey(content));
                previousKids.add(kid);
            }
        } catch (Exception e) {
            log.warn("⚠️ KeyManager: falha ao carregar chaves arquivadas, seguindo só com a atual.", e);
        }
    }

    // --- Rotação: persistência ---

    private void archivePublicKey(String kid, RSAPublicKey publicKey) throws IOException {
        Path target = archiveDir.resolve(kid + ".pub.pem");
        if (!Files.exists(target)) {
            writePem(target, "PUBLIC", publicKey.getEncoded());
        }
    }

    private void appendArchiveHistory(String kid) throws IOException {
        Path historyFile = archiveDir.resolve(ARCHIVE_HISTORY_FILE);
        Files.writeString(historyFile, kid + System.lineSeparator(),
                StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
    }

    /** Mantém só as últimas N chaves (atual + N-1 anteriores); descarta o resto do keyring e do arquivo. */
    private List<String> enforceRetention() {
        int retention = Math.max(1, jwtProperties.getKeyRetentionCount());
        List<String> removed = new java.util.ArrayList<>();
        while (previousKids.size() > retention - 1) {
            String oldest = previousKids.remove(0);
            publicKeysByKid.remove(oldest);
            removed.add(oldest);
            try {
                Files.deleteIfExists(archiveDir.resolve(oldest + ".pub.pem"));
            } catch (IOException e) {
                log.warn("⚠️ KeyManager: não consegui remover chave arquivada expirada kid={}", oldest, e);
            }
        }
        if (!removed.isEmpty()) {
            log.info("🧹 KeyManager: chaves fora da janela de retenção removidas: {}", removed);
        }
        return removed;
    }

    // --- Encoding / helpers ---

    private RSAPublicKey decodePublicKey(String base64Content) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64Content);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }

    private RSAPrivateKey decodePrivateKey(String base64Content) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64Content);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    private String sanitizeKey(String key, String type) {
        String header = "-----BEGIN " + type + " KEY-----";
        String footer = "-----END " + type + " KEY-----";
        return key.replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s+", "");
    }

    private void writePem(Path path, String type, byte[] der) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(type).append(" KEY-----\n");
        for (int i = 0; i < base64.length(); i += PEM_LINE_LENGTH) {
            pem.append(base64, i, Math.min(i + PEM_LINE_LENGTH, base64.length())).append('\n');
        }
        pem.append("-----END ").append(type).append(" KEY-----\n");
        Files.writeString(path, pem.toString(), StandardCharsets.UTF_8);
    }

    private Path resolveArchiveDir(Path privateKeyPath) {
        if (jwtProperties.getKeyArchiveDir() != null && !jwtProperties.getKeyArchiveDir().isBlank()) {
            return Path.of(jwtProperties.getKeyArchiveDir());
        }
        Path parent = privateKeyPath.getParent();
        return parent != null ? parent.resolve("archive") : Path.of("archive");
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
