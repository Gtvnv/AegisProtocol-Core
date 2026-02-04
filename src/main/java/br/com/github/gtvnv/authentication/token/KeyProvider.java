package br.com.github.gtvnv.authentication.token;

import org.springframework.stereotype.Component;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
public class KeyProvider {

    private final KeyPair keyPair;

    public KeyProvider() {
        try {
            // Gera um par de chaves RSA 2048-bit toda vez que o app inicia
            // Em produção, isso viria de um arquivo ou cofre (Vault)
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            this.keyPair = keyGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro fatal: Algoritmo RSA não disponível no ambiente", e);
        }
    }

    // Este é o método que estava faltando ou não estava visível
    public KeyPair getKeyPair() {
        return keyPair;
    }
}