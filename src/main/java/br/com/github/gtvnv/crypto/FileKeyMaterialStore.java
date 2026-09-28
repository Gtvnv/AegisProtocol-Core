package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

/**
 * KeyMaterialStore padrão — o par de chaves e o histórico de rotação vivem
 * em arquivos locais (mesma pasta configurada em aegis.jwt.*-key-path).
 * Comportamento idêntico ao que era inline em KeyManagerService antes do
 * satélite KMS/Vault real: se o arquivo não existir no filesystem, cai pro
 * classpath (fixture de teste) e vira somente-leitura — rotação fica
 * indisponível nesse caso.
 */
@RequiredArgsConstructor
public class FileKeyMaterialStore implements KeyMaterialStore {

    private static final String ARCHIVE_HISTORY_FILE = "history.txt";

    private final JwtProperties jwtProperties;

    private record Loaded(String sanitizedContent, Path path, boolean fromFilesystem) {}

    @Override
    public LoadedKeyMaterial loadCurrent() throws IOException {
        Loaded publicLoaded = load(jwtProperties.getPublicKeyPath(), "PUBLIC");
        Loaded privateLoaded = load(jwtProperties.getPrivateKeyPath(), "PRIVATE");

        RSAPublicKey publicKey = PemUtils.decodePublicKey(publicLoaded.sanitizedContent());
        RSAPrivateKey privateKey = PemUtils.decodePrivateKey(privateLoaded.sanitizedContent());
        boolean writable = publicLoaded.fromFilesystem() && privateLoaded.fromFilesystem();

        return new LoadedKeyMaterial(privateKey, publicKey, writable);
    }

    @Override
    public void writeCurrent(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws IOException {
        writePem(privateKeyPath(), "PRIVATE", privateKey.getEncoded());
        writePem(publicKeyPath(), "PUBLIC", publicKey.getEncoded());
    }

    @Override
    public void archivePublicKey(String kid, RSAPublicKey publicKey) throws IOException {
        Path archiveDir = archiveDir();
        Files.createDirectories(archiveDir);
        Path target = archiveDir.resolve(kid + ".pub.pem");
        if (!Files.exists(target)) {
            writePem(target, "PUBLIC", publicKey.getEncoded());
        }
    }

    @Override
    public Optional<RSAPublicKey> loadArchivedPublicKey(String kid) throws IOException {
        Path file = archiveDir().resolve(kid + ".pub.pem");
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        String content = PemUtils.sanitize(Files.readString(file, StandardCharsets.UTF_8), "PUBLIC");
        return Optional.of(PemUtils.decodePublicKey(content));
    }

    @Override
    public List<String> loadArchiveHistory() throws IOException {
        Path historyFile = archiveDir().resolve(ARCHIVE_HISTORY_FILE);
        if (!Files.isDirectory(archiveDir()) || !Files.exists(historyFile)) {
            return List.of();
        }
        return Files.readAllLines(historyFile, StandardCharsets.UTF_8).stream()
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .toList();
    }

    @Override
    public void appendArchiveHistory(String kid) throws IOException {
        Path archiveDir = archiveDir();
        Files.createDirectories(archiveDir);
        Files.writeString(archiveDir.resolve(ARCHIVE_HISTORY_FILE), kid + System.lineSeparator(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    @Override
    public void deleteArchivedKey(String kid) throws IOException {
        Files.deleteIfExists(archiveDir().resolve(kid + ".pub.pem"));
    }

    // --- helpers ---

    private Loaded load(String path, String type) throws IOException {
        FileSystemResource fsResource = new FileSystemResource(path);
        if (fsResource.exists()) {
            String content = StreamUtils.copyToString(fsResource.getInputStream(), StandardCharsets.UTF_8);
            return new Loaded(PemUtils.sanitize(content, type), fsResource.getFile().toPath(), true);
        }
        ClassPathResource cpResource = new ClassPathResource(path);
        String content = StreamUtils.copyToString(cpResource.getInputStream(), StandardCharsets.UTF_8);
        return new Loaded(PemUtils.sanitize(content, type), null, false);
    }

    private void writePem(Path path, String type, byte[] der) throws IOException {
        Files.writeString(path, PemUtils.encode(der, type), StandardCharsets.UTF_8);
    }

    private Path privateKeyPath() {
        return Path.of(jwtProperties.getPrivateKeyPath());
    }

    private Path publicKeyPath() {
        return Path.of(jwtProperties.getPublicKeyPath());
    }

    private Path archiveDir() {
        if (jwtProperties.getKeyArchiveDir() != null && !jwtProperties.getKeyArchiveDir().isBlank()) {
            return Path.of(jwtProperties.getKeyArchiveDir());
        }
        Path parent = privateKeyPath().getParent();
        return parent != null ? parent.resolve("archive") : Path.of("archive");
    }
}
