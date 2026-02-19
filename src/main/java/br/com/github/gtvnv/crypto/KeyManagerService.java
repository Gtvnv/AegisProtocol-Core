package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.config.JwtProperties;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeyManagerService {

    private final JwtProperties jwtProperties;

    @Getter
    private RSAPublicKey publicKey;
    @Getter
    private RSAPrivateKey privateKey;

    @PostConstruct
    public void loadKeys() {
        try {
            log.info("🔐 KeyManager: Carregando par de chaves RSA...");

            // 1. Carregar Pública
            String publicContent = loadKeyContent(jwtProperties.getPublicKeyPath());
            publicContent = sanitizeKey(publicContent, "PUBLIC");
            byte[] publicBytes = Base64.getDecoder().decode(publicContent);
            this.publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicBytes));

            // 2. Carregar Privada
            String privateContent = loadKeyContent(jwtProperties.getPrivateKeyPath());
            privateContent = sanitizeKey(privateContent, "PRIVATE");
            byte[] privateBytes = Base64.getDecoder().decode(privateContent);
            this.privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

            log.info("✅ KeyManager: Chaves carregadas com sucesso!");
        } catch (Exception e) {
            log.error("❌ KeyManager: Falha crítica ao carregar chaves.", e);
            throw new RuntimeException("Falha na inicialização criptográfica", e);
        }
    }

    // --- Helpers Privados ---

    private String loadKeyContent(String path) throws Exception {
        FileSystemResource fsResource = new FileSystemResource(path);
        if (fsResource.exists()) {
            return StreamUtils.copyToString(fsResource.getInputStream(), StandardCharsets.UTF_8);
        }
        ClassPathResource cpResource = new ClassPathResource(path);
        return StreamUtils.copyToString(cpResource.getInputStream(), StandardCharsets.UTF_8);
    }

    private String sanitizeKey(String key, String type) {
        String header = "-----BEGIN " + type + " KEY-----";
        String footer = "-----END " + type + " KEY-----";
        return key.replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s+", "");
    }
}