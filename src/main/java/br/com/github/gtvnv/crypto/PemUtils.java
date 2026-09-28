package br.com.github.gtvnv.crypto;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Sanitização/encoding/decodificação PEM compartilhada entre os
 * KeyMaterialStore (file, vault, ...) — extraído do KeyManagerService
 * original no satélite KMS/Vault real, pra não duplicar a mesma lógica em
 * cada provider.
 */
public final class PemUtils {

    private static final int PEM_LINE_LENGTH = 64;

    private PemUtils() {}

    public static RSAPublicKey decodePublicKey(String base64Content) throws IOException {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64Content);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (Exception e) {
            throw new IOException("Falha ao decodificar chave pública", e);
        }
    }

    public static RSAPrivateKey decodePrivateKey(String base64Content) throws IOException {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64Content);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (Exception e) {
            throw new IOException("Falha ao decodificar chave privada", e);
        }
    }

    /** Remove header/footer "-----BEGIN X KEY-----"/"-----END X KEY-----" e todo whitespace — sobra só o base64. */
    public static String sanitize(String pem, String type) {
        String header = "-----BEGIN " + type + " KEY-----";
        String footer = "-----END " + type + " KEY-----";
        return pem.replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s+", "");
    }

    /** Envolve DER bytes num PEM formatado (header/footer + base64 quebrado em linhas de 64 chars). */
    public static String encode(byte[] der, String type) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(type).append(" KEY-----\n");
        for (int i = 0; i < base64.length(); i += PEM_LINE_LENGTH) {
            pem.append(base64, i, Math.min(i + PEM_LINE_LENGTH, base64.length())).append('\n');
        }
        pem.append("-----END ").append(type).append(" KEY-----\n");
        return pem.toString();
    }
}
