package br.com.github.gtvnv.privacy.service;

import br.com.github.gtvnv.privacy.domain.PrivacySubjectKey;
import br.com.github.gtvnv.privacy.repository.PrivacySubjectKeyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Satélite IAM Self-Service — cobre a propriedade central do PrivacyGate:
 * determinístico enquanto a chave existir, irreversível depois de forget().
 */
@ExtendWith(MockitoExtension.class)
class PrivacyGateServiceTest {

    @Mock private PrivacySubjectKeyRepository repository;

    private PrivacyGateService gate;

    private PrivacyGateService newGate() {
        return new PrivacyGateService(repository);
    }

    // -----------------------------------------------------------------------
    // Determinismo enquanto a chave existe
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Mesmo titular produz sempre o mesmo pseudônimo enquanto a chave existir")
    void pseudonymize_SameSubject_IsDeterministic() {
        gate = newGate();
        PrivacySubjectKey key = PrivacySubjectKey.builder()
            .subjectId("alice").secretKeyBase64(fixedBase64Key()).createdAt(Instant.now()).build();
        when(repository.findById("alice")).thenReturn(Optional.of(key));

        String p1 = gate.pseudonymize("alice");
        String p2 = gate.pseudonymize("alice");

        assertThat(p1).isEqualTo(p2);
        assertThat(p1).startsWith("anon_");
        verify(repository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("Titulares diferentes produzem pseudônimos diferentes")
    void pseudonymize_DifferentSubjects_ProduceDifferentPseudonyms() {
        gate = newGate();
        when(repository.findById("alice")).thenReturn(Optional.of(
            PrivacySubjectKey.builder().subjectId("alice").secretKeyBase64(fixedBase64Key()).createdAt(Instant.now()).build()));
        when(repository.findById("bob")).thenReturn(Optional.of(
            PrivacySubjectKey.builder().subjectId("bob").secretKeyBase64(fixedBase64Key()).createdAt(Instant.now()).build()));

        String alice = gate.pseudonymize("alice");
        String bob = gate.pseudonymize("bob");

        assertThat(alice).isNotEqualTo(bob);
    }

    @Test
    @DisplayName("Primeira chamada para um titular novo cria a chave (get-or-create)")
    void pseudonymize_NewSubject_CreatesKey() {
        gate = newGate();
        when(repository.findById("new-user")).thenReturn(Optional.empty());
        ArgumentCaptor<PrivacySubjectKey> captor = ArgumentCaptor.forClass(PrivacySubjectKey.class);
        when(repository.saveAndFlush(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        String pseudonym = gate.pseudonymize("new-user");

        assertThat(pseudonym).isNotBlank();
        assertThat(captor.getValue().getSubjectId()).isEqualTo("new-user");
        assertThat(captor.getValue().getSecretKeyBase64()).isNotBlank();
    }

    @Test
    @DisplayName("subjectId nulo ou em branco é devolvido como está — nada a pseudonimizar")
    void pseudonymize_BlankSubject_PassesThrough() {
        gate = newGate();

        assertThat(gate.pseudonymize(null)).isNull();
        assertThat(gate.pseudonymize("")).isEmpty();
        verifyNoInteractions(repository);
    }

    // -----------------------------------------------------------------------
    // Crypto-shredding
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("forget() apaga a chave do titular — crypto-shredding")
    void forget_DeletesKey() {
        gate = newGate();
        gate.forget("alice");
        verify(repository).deleteById("alice");
    }

    @Test
    @DisplayName("Depois de forget(), o mesmo titular recebe uma chave (e pseudônimo) NOVA — a mapeação antiga é irrecuperável")
    void pseudonymize_AfterForget_ProducesUnrelatedPseudonym() {
        gate = newGate();
        PrivacySubjectKey originalKey = PrivacySubjectKey.builder()
            .subjectId("alice").secretKeyBase64(fixedBase64Key()).createdAt(Instant.now()).build();
        when(repository.findById("alice")).thenReturn(Optional.of(originalKey), Optional.empty());
        when(repository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

        String beforeForget = gate.pseudonymize("alice");
        gate.forget("alice");
        String afterForget = gate.pseudonymize("alice"); // simula reuso do mesmo username por outra pessoa

        assertThat(afterForget).isNotEqualTo(beforeForget);
        verify(repository).deleteById("alice");
    }

    @Test
    @DisplayName("forget() com subjectId nulo é um no-op seguro")
    void forget_BlankSubject_NoOp() {
        gate = newGate();
        gate.forget(null);
        gate.forget("");
        verifyNoInteractions(repository);
    }

    // -----------------------------------------------------------------------
    // Corrida na criação da chave
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Corrida na criação: quem perde o INSERT usa a chave de quem ganhou, nunca gera uma segunda")
    void pseudonymize_ConcurrentFirstCreate_UsesWinnersKey() {
        gate = newGate();
        PrivacySubjectKey winnerKey = PrivacySubjectKey.builder()
            .subjectId("carol").secretKeyBase64(fixedBase64Key()).createdAt(Instant.now()).build();

        when(repository.findById("carol"))
            .thenReturn(Optional.empty())      // primeira leitura: ninguém criou ainda
            .thenReturn(Optional.of(winnerKey)); // leitura pós-corrida: já existe
        when(repository.saveAndFlush(any()))
            .thenThrow(new org.springframework.dao.DataIntegrityViolationException("duplicate key"));

        String pseudonym = gate.pseudonymize("carol");

        assertThat(pseudonym).isEqualTo("anon_" + expectedHmacHex(winnerKey.getSecretKeyBase64(), "carol"));
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private String fixedBase64Key() {
        return java.util.Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes());
    }

    private String expectedHmacHex(String secretBase64, String data) {
        try {
            byte[] secret = java.util.Base64.getDecoder().decode(secretBase64);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
            byte[] result = mac.doFinal(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(result).substring(0, 32);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
