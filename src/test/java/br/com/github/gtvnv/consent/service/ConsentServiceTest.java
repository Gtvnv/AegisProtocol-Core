package br.com.github.gtvnv.consent.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.consent.config.ConsentProperties;
import br.com.github.gtvnv.consent.domain.ConsentRecord;
import br.com.github.gtvnv.consent.repository.ConsentRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Satélite Consent Ledger — captura versionada + evidência no Ômega.
 */
@ExtendWith(MockitoExtension.class)
class ConsentServiceTest {

    @Mock private ConsentRecordRepository repository;
    @Mock private AuditEventPublisher chainPublisher;

    private ConsentProperties properties;
    private ConsentService service;

    @BeforeEach
    void setUp() {
        properties = new ConsentProperties();
        properties.setCurrentVersion("1.0");
        properties.setDocumentUrl("https://example.com/terms-1.0");
        service = new ConsentService(repository, properties, chainPublisher);
    }

    // -----------------------------------------------------------------------
    // validateVersion — fail fast, sem efeito colateral
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("validateVersion aceita a versão vigente sem tocar em nada")
    void validateVersion_CurrentVersion_DoesNotThrow() {
        assertThatCode(() -> service.validateVersion("1.0")).doesNotThrowAnyException();
        verifyNoInteractions(repository, chainPublisher);
    }

    @Test
    @DisplayName("validateVersion rejeita versão nula")
    void validateVersion_Null_Throws() {
        assertThatThrownBy(() -> service.validateVersion(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Consentimento obrigatório");
    }

    @Test
    @DisplayName("validateVersion rejeita versão em branco")
    void validateVersion_Blank_Throws() {
        assertThatThrownBy(() -> service.validateVersion("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Consentimento obrigatório");
    }

    @Test
    @DisplayName("validateVersion rejeita versão desatualizada")
    void validateVersion_OutdatedVersion_Throws() {
        assertThatThrownBy(() -> service.validateVersion("0.9"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("0.9")
            .hasMessageContaining("1.0");
    }

    // -----------------------------------------------------------------------
    // recordConsent — grava a tabela E audita no Ômega
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("recordConsent salva o registro e publica CONSENT_GIVEN")
    void recordConsent_SavesRecordAndPublishesAuditEvent() {
        ArgumentCaptor<ConsentRecord> captor = ArgumentCaptor.forClass(ConsentRecord.class);
        when(repository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        service.recordConsent("alice", "1.0", "10.0.0.1");

        assertThat(captor.getValue().getSubjectId()).isEqualTo("alice");
        assertThat(captor.getValue().getVersion()).isEqualTo("1.0");
        assertThat(captor.getValue().getRevokedAt()).isNull();
        verify(chainPublisher).publishConsentEvent(
            eq(AuditEventType.CONSENT_GIVEN), eq("alice"), eq("1.0"), eq("10.0.0.1"));
    }

    // -----------------------------------------------------------------------
    // withdrawConsent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("withdrawConsent marca revokedAt no consentimento ativo e audita CONSENT_WITHDRAWN")
    void withdrawConsent_MarksActiveRecordRevoked() {
        ConsentRecord active = ConsentRecord.builder()
            .subjectId("alice").version("1.0").consentedAt(Instant.now()).build();
        when(repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc("alice"))
            .thenReturn(Optional.of(active));

        service.withdrawConsent("alice", "10.0.0.1");

        assertThat(active.getRevokedAt()).isNotNull();
        verify(repository).save(active);
        verify(chainPublisher).publishConsentEvent(
            eq(AuditEventType.CONSENT_WITHDRAWN), eq("alice"), isNull(), eq("10.0.0.1"));
    }

    @Test
    @DisplayName("withdrawConsent sem consentimento ativo ainda assim audita a tentativa")
    void withdrawConsent_NoActiveRecord_StillAudits() {
        when(repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc("ghost"))
            .thenReturn(Optional.empty());

        service.withdrawConsent("ghost", "10.0.0.1");

        verify(repository, never()).save(any());
        verify(chainPublisher).publishConsentEvent(
            eq(AuditEventType.CONSENT_WITHDRAWN), eq("ghost"), isNull(), any());
    }

    // -----------------------------------------------------------------------
    // hasValidCurrentConsent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("hasValidCurrentConsent é true só com consentimento ativo NA versão vigente")
    void hasValidCurrentConsent_ActiveAndCurrentVersion_True() {
        when(repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc("alice"))
            .thenReturn(Optional.of(ConsentRecord.builder().subjectId("alice").version("1.0").consentedAt(Instant.now()).build()));

        assertThat(service.hasValidCurrentConsent("alice")).isTrue();
    }

    @Test
    @DisplayName("hasValidCurrentConsent é false se a versão consentida ficou desatualizada")
    void hasValidCurrentConsent_StaleVersion_False() {
        when(repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc("alice"))
            .thenReturn(Optional.of(ConsentRecord.builder().subjectId("alice").version("0.9").consentedAt(Instant.now()).build()));

        assertThat(service.hasValidCurrentConsent("alice")).isFalse();
    }

    @Test
    @DisplayName("hasValidCurrentConsent é false sem nenhum registro")
    void hasValidCurrentConsent_NoRecord_False() {
        when(repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc("nobody"))
            .thenReturn(Optional.empty());

        assertThat(service.hasValidCurrentConsent("nobody")).isFalse();
    }

    // -----------------------------------------------------------------------
    // forgetAll — usado pela exclusão de conta
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("forgetAll delega a exclusão física ao repositório")
    void forgetAll_DeletesBySubjectId() {
        service.forgetAll("alice");
        verify(repository).deleteBySubjectId("alice");
    }
}
