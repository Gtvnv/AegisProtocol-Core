package br.com.github.gtvnv.privacy.service;

import br.com.github.gtvnv.privacy.domain.PrivacySubjectKey;
import br.com.github.gtvnv.privacy.repository.PrivacySubjectKeyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Satélite IAM Self-Service — PrivacyGate: pseudonimiza o 'actor' antes de
 * qualquer escrita no Ômega (ver ChainAuditListener) e viabiliza o direito
 * ao esquecimento (LGPD Art. 18 / GDPR Art. 17) sem violar o WORM da cadeia.
 *
 * Como funciona:
 *  - Cada titular (username) ganha uma chave HMAC própria na primeira vez
 *    que algo seu precisa ser auditado (get-or-create).
 *  - pseudonymize(subjectId) é determinístico ENQUANTO a chave existir — o
 *    mesmo titular sempre produz o mesmo pseudônimo, preservando a
 *    sequência por ator que o Ômega exige (AuditChainService).
 *  - forget(subjectId) destrói a chave (crypto-shredding): as entries já
 *    gravadas continuam intactas e com hash válido — só deixam de poder
 *    ser re-associadas ao titular (ninguém mais consegue recomputar o
 *    pseudônimo a partir do username).
 *
 * Ressalva documentada no mapeamento de compliance: enquanto a chave existir,
 * o pseudônimo ainda é dado pessoal sob a LGPD (Art. 13 §4º) / GDPR (Consid.
 * 26) — este gate cobre o esquecimento, mas não substitui controle de acesso
 * sobre esta tabela.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PrivacyGateService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String PSEUDONYM_PREFIX = "anon_";
    private static final int SECRET_KEY_BYTES = 32; // 256 bits

    // Reaproveitada entre chamadas: SecureRandom já se autosemeia e é
    // thread-safe (nextBytes é sincronizado internamente na JVM) — instanciar
    // um novo objeto a cada chave desperdiça o custo de inicialização/coleta
    // de entropia sem ganhar nada em segurança.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final PrivacySubjectKeyRepository repository;

    @Transactional
    public String pseudonymize(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            return subjectId;
        }
        PrivacySubjectKey key = getOrCreateKey(subjectId);
        return PSEUDONYM_PREFIX + hmac(key.getSecretKeyBase64(), subjectId);
    }

    @Transactional
    public void forget(String subjectId) {
        if (subjectId == null || subjectId.isBlank()) {
            return;
        }
        repository.deleteById(subjectId);
        log.warn("PrivacyGate: chave do titular destruída (crypto-shredding) — subjectId={}", subjectId);
    }

    public boolean hasKey(String subjectId) {
        return subjectId != null && repository.existsById(subjectId);
    }

    private PrivacySubjectKey getOrCreateKey(String subjectId) {
        return repository.findById(subjectId).orElseGet(() -> {
            try {
                return repository.saveAndFlush(newKeyFor(subjectId));
            } catch (DataIntegrityViolationException concurrentCreate) {
                // Duas requisições concorrentes criando a chave do mesmo titular
                // pela primeira vez — quem perdeu a corrida usa a chave do vencedor,
                // nunca gera uma segunda (isso quebraria o determinismo do pseudônimo).
                return repository.findById(subjectId).orElseThrow(() -> concurrentCreate);
            }
        });
    }

    private PrivacySubjectKey newKeyFor(String subjectId) {
        byte[] secret = new byte[SECRET_KEY_BYTES];
        SECURE_RANDOM.nextBytes(secret);
        return PrivacySubjectKey.builder()
                .subjectId(subjectId)
                .secretKeyBase64(Base64.getEncoder().encodeToString(secret))
                .createdAt(Instant.now())
                .build();
    }

    private String hmac(String secretKeyBase64, String data) {
        try {
            byte[] secret = Base64.getDecoder().decode(secretKeyBase64);
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] result = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            // 128 bits (32 hex chars) bastam para um pseudônimo — não é uma
            // assinatura que precise da força total do HMAC-SHA256.
            return HexFormat.of().formatHex(result).substring(0, 32);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao computar pseudônimo HMAC", e);
        }
    }
}
