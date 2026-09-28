package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Satélite KMS/Secrets: cobre a rotação de chave RS256 sem downtime — o coração
 * do que fecha (parcialmente) o gap ISO 27001 A.8.24 no mapeamento de compliance.
 */
class KeyManagerServiceTest {

    @TempDir
    Path tempDir;

    private JwtProperties jwtProperties;

    @BeforeEach
    void setUp() throws Exception {
        // Par inicial "pré-existente" — simula uma chave gerada antes desta feature.
        KeyPair initialPair = KeyGeneratorUtils.generateRsaKey();
        writePem(tempDir.resolve("private_key.pem"), "PRIVATE", initialPair.getPrivate().getEncoded());
        writePem(tempDir.resolve("public_key.pem"), "PUBLIC", initialPair.getPublic().getEncoded());

        jwtProperties = new JwtProperties();
        jwtProperties.setPrivateKeyPath(tempDir.resolve("private_key.pem").toString());
        jwtProperties.setPublicKeyPath(tempDir.resolve("public_key.pem").toString());
        jwtProperties.setKeyRetentionCount(2);
    }

    private KeyManagerService newlyLoaded() {
        KeyManagerService service = new KeyManagerService(jwtProperties, new FileKeyMaterialStore(jwtProperties));
        service.loadKeys();
        return service;
    }

    @Test
    @DisplayName("Ao carregar, expõe a chave atual com um kid determinístico")
    void loadKeys_ExposesCurrentKeyWithKid() {
        KeyManagerService service = newlyLoaded();

        assertNotNull(service.getCurrentKid());
        assertNotNull(service.getPublicKey());
        assertNotNull(service.getPrivateKey());
        assertEquals(1, service.getVerificationKeys().size());
        assertTrue(service.getVerificationKeys().containsKey(service.getCurrentKid()));
    }

    @Test
    @DisplayName("rotate() troca a chave de assinatura mas mantém a anterior verificável")
    void rotate_KeepsPreviousKeyVerifiable() {
        KeyManagerService service = newlyLoaded();
        String originalKid = service.getCurrentKid();
        RSAPublicKey originalPublicKey = service.getPublicKey();

        KeyManagerService.RotationResult result = service.rotate();

        assertEquals(originalKid, result.previousKid());
        assertNotEquals(originalKid, result.newKid());
        assertEquals(result.newKid(), service.getCurrentKid());
        assertNotEquals(originalPublicKey, service.getPublicKey());

        // Token assinado ANTES da rotação continua verificável — sem downtime.
        assertEquals(originalPublicKey, service.getVerificationKey(originalKid));
        assertEquals(service.getPublicKey(), service.getVerificationKey(result.newKid()));
    }

    @Test
    @DisplayName("Um kid desconhecido é rejeitado na verificação")
    void getVerificationKey_UnknownKid_Throws() {
        KeyManagerService service = newlyLoaded();

        assertThrows(SignatureException.class, () -> service.getVerificationKey("kid-que-nao-existe"));
    }

    @Test
    @DisplayName("Retenção descarta chaves fora da janela configurada")
    void rotate_PrunesKeysBeyondRetention() {
        KeyManagerService service = newlyLoaded(); // retention = 2
        String kid1 = service.getCurrentKid();

        KeyManagerService.RotationResult r2 = service.rotate();
        String kid2 = r2.newKid();

        KeyManagerService.RotationResult r3 = service.rotate();
        String kid3 = r3.newKid();

        // Retenção 2 = atual + 1 anterior. kid1 (a mais antiga) deve ter saído.
        assertEquals(2, service.getVerificationKeys().size());
        assertThrows(SignatureException.class, () -> service.getVerificationKey(kid1));
        assertNotNull(service.getVerificationKey(kid2));
        assertNotNull(service.getVerificationKey(kid3));
        assertFalse(Files.exists(tempDir.resolve("archive").resolve(kid1 + ".pub.pem")),
                "chave arquivada fora da retenção deveria ter sido removida do disco");
    }

    @Test
    @DisplayName("Após reiniciar o serviço, o histórico de rotação é restaurado do disco")
    void loadKeys_RestoresRotationHistoryAcrossRestarts() {
        KeyManagerService first = newlyLoaded();
        KeyManagerService.RotationResult result = first.rotate();

        // Nova instância = simula um restart do processo, lendo os mesmos arquivos.
        KeyManagerService second = newlyLoaded();

        assertEquals(result.newKid(), second.getCurrentKid());
        assertNotNull(second.getVerificationKey(result.previousKid()),
                "chave anterior deveria continuar verificável após o restart");
    }

    @Test
    @DisplayName("rotate() falha de forma explícita quando as chaves não são graváveis")
    void rotate_WithoutFilesystemBacking_Throws() throws Exception {
        JwtProperties classpathProps = new JwtProperties();
        // Caminho existente só no classpath de teste (somente leitura).
        classpathProps.setPrivateKeyPath("testkeys/private_key.pem");
        classpathProps.setPublicKeyPath("testkeys/public_key.pem");

        KeyManagerService service = new KeyManagerService(classpathProps, new FileKeyMaterialStore(classpathProps));
        service.loadKeys();

        assertThrows(IllegalStateException.class, service::rotate);
    }

    private void writePem(Path path, String type, byte[] der) throws IOException {
        String base64 = Base64.getEncoder().encodeToString(der);
        String pem = "-----BEGIN " + type + " KEY-----\n" + base64 + "\n-----END " + type + " KEY-----\n";
        Files.writeString(path, pem, StandardCharsets.UTF_8);
    }
}
