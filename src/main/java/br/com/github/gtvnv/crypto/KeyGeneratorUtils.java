package br.com.github.gtvnv.crypto;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
public class KeyGeneratorUtils {

    /**
     * Gera um novo par de chaves RSA de 2048 bits.
     * Operação pesada (CPU intensive), deve ser feita apenas na rotação.
     */
    public static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algoritmo RSA não disponível no ambiente Java", e);
        }
    }
}