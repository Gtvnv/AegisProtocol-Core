package br.com.github.gtvnv.audit.chain.integration;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.dto.ChainVerificationReport;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import br.com.github.gtvnv.audit.chain.service.AuditHashEngine;
import br.com.github.gtvnv.audit.chain.service.ChainIntegrityVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Teste de integração do Cryptographic Audit Chain com H2 em memória.
 *
 * @DataJpaTest configura H2 automaticamente.
 * @Transactional(NOT_SUPPORTED) na classe garante que os @Transactional(REQUIRES_NEW)
 * do AuditChainService funcionem corretamente sem interferência de transação externa.
 *
 * Tampering é simulado via repository.save() com entidade modificada — isto funciona
 * porque, sem transação ativa, cada chamada de repositório gerencia sua própria TX.
 */
@DataJpaTest
@Import(AuditChainIntegrationTest.TestConfig.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditChainIntegrationTest {

    @Configuration
    static class TestConfig {
        @Bean ObjectMapper objectMapper() { return new ObjectMapper(); }
        @Bean AuditHashEngine auditHashEngine() { return new AuditHashEngine(); }

        @Bean
        AuditChainService auditChainService(AuditChainRepository repo,
                                             AuditHashEngine engine,
                                             ObjectMapper mapper) {
            return new AuditChainService(repo, engine, mapper);
        }

        @Bean
        ChainIntegrityVerifier chainIntegrityVerifier(AuditChainRepository repo,
                                                       AuditHashEngine engine) {
            return new ChainIntegrityVerifier(repo, engine);
        }
    }

    @Autowired private AuditChainRepository   repository;
    @Autowired private AuditChainService      chainService;
    @Autowired private ChainIntegrityVerifier verifier;

    @AfterEach
    void cleanUp() {
        // deleteAll() usa sua própria TX (REQUIRED) — limpa os dados das TXs REQUIRES_NEW
        repository.deleteAll();
    }

    // -----------------------------------------------------------------------
    // Encadeamento básico com banco real
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Primeiro entry persiste com previousHash='GENESIS' e sequenceNumber=1")
    void append_FirstEntry_PersistedWithGenesisAndSeq1() {
        AuditChainEntry entry = chainService.append(
            AuditEventType.LOGIN_SUCCESS, "alice",
            "jti-001", "127.0.0.1", null, null, "test login", Map.of("ip", "127.0.0.1"));

        assertThat(entry).isNotNull();
        assertThat(entry.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(entry.getSequenceNumber()).isEqualTo(1L);
        assertThat(entry.getSelfHash()).isNotBlank().hasSize(64).matches("[0-9a-f]+");
        assertThat(entry.getId()).isNotBlank();
        assertThat(entry.getPayloadJson()).contains("ip").contains("127.0.0.1");
    }

    @Test
    @DisplayName("Segundo entry encadeia o selfHash do primeiro como previousHash")
    void append_TwoEntries_SecondChainsPreviousHash() {
        AuditChainEntry first  = chainService.append(AuditEventType.LOGIN_SUCCESS,       "alice", null, null, null, null, null, null);
        AuditChainEntry second = chainService.append(AuditEventType.ABAC_DECISION_PERMIT,"alice", null, null, null, null, null, null);

        assertThat(second.getPreviousHash()).isEqualTo(first.getSelfHash());
        assertThat(second.getSequenceNumber()).isEqualTo(2L);
    }

    @Test
    @DisplayName("Cadeia de 5 entries: cada entry referencia o hash do anterior")
    void append_FiveEntries_FullChainIsLinked() {
        AuditEventType[] types = {
            AuditEventType.LOGIN_SUCCESS,
            AuditEventType.TOKEN_ISSUED,
            AuditEventType.ABAC_DECISION_PERMIT,
            AuditEventType.ABAC_DECISION_PERMIT,
            AuditEventType.LOGOUT_SUCCESS
        };

        AuditChainEntry prev = null;
        for (int i = 0; i < types.length; i++) {
            AuditChainEntry current = chainService.append(types[i], "alice", null, null, null, null, null, null);
            if (prev != null) {
                assertThat(current.getPreviousHash()).isEqualTo(prev.getSelfHash());
            } else {
                assertThat(current.getPreviousHash()).isEqualTo("GENESIS");
            }
            assertThat(current.getSequenceNumber()).isEqualTo(i + 1L);
            prev = current;
        }
    }

    // -----------------------------------------------------------------------
    // Independência entre atores
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Dois atores distintos têm cadeias independentes — ambos começam com GENESIS")
    void append_TwoActors_IndependentChainsStartWithGenesis() {
        AuditChainEntry alice = chainService.append(AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        AuditChainEntry bob   = chainService.append(AuditEventType.LOGIN_SUCCESS, "bob",   null, null, null, null, null, null);

        assertThat(alice.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(bob.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(alice.getSequenceNumber()).isEqualTo(1L);
        assertThat(bob.getSequenceNumber()).isEqualTo(1L);
        assertThat(alice.getSelfHash()).isNotEqualTo(bob.getSelfHash());
    }

    @Test
    @DisplayName("Entries intercalados de dois atores mantêm numerações independentes")
    void append_InterleavedActors_SequencesAreIndependent() {
        chainService.append(AuditEventType.LOGIN_SUCCESS,  "alice", null, null, null, null, null, null);
        chainService.append(AuditEventType.LOGIN_SUCCESS,  "bob",   null, null, null, null, null, null);
        AuditChainEntry alice2 = chainService.append(AuditEventType.LOGOUT_SUCCESS, "alice", null, null, null, null, null, null);
        AuditChainEntry bob2   = chainService.append(AuditEventType.LOGOUT_SUCCESS, "bob",   null, null, null, null, null, null);

        assertThat(alice2.getSequenceNumber()).isEqualTo(2L);
        assertThat(bob2.getSequenceNumber()).isEqualTo(2L);
    }

    // -----------------------------------------------------------------------
    // ChainIntegrityVerifier com dados reais
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cadeia recém-criada passa na verificação de integridade")
    void verify_NewChain_IsValid() {
        chainService.append(AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        chainService.append(AuditEventType.TOKEN_ISSUED,  "alice", null, null, null, null, null, null);
        chainService.append(AuditEventType.LOGOUT_SUCCESS,"alice", null, null, null, null, null, null);

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isTrue();
        assertThat(report.totalEntries()).isEqualTo(3);
        assertThat(report.firstBrokenAt()).isNull();
    }

    @Test
    @DisplayName("Cadeia vazia retorna relatório válido com 0 entries")
    void verify_EmptyChain_ValidReportWithZeroEntries() {
        ChainVerificationReport report = verifier.verify("nobody");

        assertThat(report.isValid()).isTrue();
        assertThat(report.totalEntries()).isEqualTo(0);
    }

    // -----------------------------------------------------------------------
    // Detecção de tampering via save() com campo modificado
    //
    // Estratégia: append cria entrada legítima, depois a carregamos, modificamos
    // o selfHash ou previousHash via repository.save() (merge/UPDATE no H2),
    // e verificamos se o verifier detecta a corrupção.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Adulteração de selfHash via UPDATE → detectada pelo verifier")
    void verify_TamperedSelfHash_Detected() {
        AuditChainEntry entry = chainService.append(
            AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);

        // Carrega a entidade e adultera o selfHash — simula ataque de nível DB
        AuditChainEntry tampered = repository.findById(entry.getId()).orElseThrow();
        tampered.setSelfHash("0000000000000000000000000000000000000000000000000000000000000000");
        repository.save(tampered);

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo(entry.getId());
    }

    @Test
    @DisplayName("Adulteração de previousHash do segundo entry → elo quebrado detectado")
    void verify_TamperedPreviousHashOnSecondEntry_Detected() {
        chainService.append(AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        AuditChainEntry second = chainService.append(AuditEventType.TOKEN_ISSUED, "alice", null, null, null, null, null, null);

        // Rompe o elo adulterando o previousHash
        AuditChainEntry tampered = repository.findById(second.getId()).orElseThrow();
        tampered.setPreviousHash("WRONG_PREVIOUS_HASH_BREAKS_CHAIN");
        repository.save(tampered);

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo(second.getId());
    }

    @Test
    @DisplayName("Primeiro entry com previousHash adulterado para não-GENESIS → detectado")
    void verify_FirstEntryGenesisAdulterated_Detected() {
        AuditChainEntry first = chainService.append(
            AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);

        AuditChainEntry tampered = repository.findById(first.getId()).orElseThrow();
        tampered.setPreviousHash("NOT_GENESIS_ANYMORE");
        repository.save(tampered);

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo(first.getId());
    }

    // -----------------------------------------------------------------------
    // verifyAll
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verifyAll retorna relatórios para todos os atores com dados")
    void verifyAll_MultipleActors_AllReported() {
        chainService.append(AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        chainService.append(AuditEventType.LOGIN_SUCCESS, "bob",   null, null, null, null, null, null);
        chainService.append(AuditEventType.LOGIN_SUCCESS, "carol", null, null, null, null, null, null);

        List<ChainVerificationReport> reports = verifier.verifyAll();

        assertThat(reports).hasSize(3);
        assertThat(reports).allSatisfy(r -> assertThat(r.isValid()).isTrue());
        assertThat(reports).extracting(ChainVerificationReport::actor)
            .containsExactlyInAnyOrder("alice", "bob", "carol");
    }

    @Test
    @DisplayName("verifyAll: um ator adulterado não contamina relatório dos demais")
    void verifyAll_OneActorCorrupted_OtherActorsStillValid() {
        chainService.append(AuditEventType.LOGIN_SUCCESS, "good_actor", null, null, null, null, null, null);
        AuditChainEntry badEntry = chainService.append(AuditEventType.LOGIN_SUCCESS, "bad_actor",  null, null, null, null, null, null);

        // Adultera apenas o bad_actor
        AuditChainEntry tampered = repository.findById(badEntry.getId()).orElseThrow();
        tampered.setSelfHash("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead");
        repository.save(tampered);

        List<ChainVerificationReport> reports = verifier.verifyAll();

        assertThat(reports).anySatisfy(r -> {
            assertThat(r.actor()).isEqualTo("good_actor");
            assertThat(r.isValid()).isTrue();
        });
        assertThat(reports).anySatisfy(r -> {
            assertThat(r.actor()).isEqualTo("bad_actor");
            assertThat(r.isValid()).isFalse();
        });
    }

    // -----------------------------------------------------------------------
    // Persistência e unicidade de selfHash
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("selfHashes de dois entries distintos nunca colidem")
    void append_TwoDistinctEntries_HaveDistinctSelfHashes() {
        AuditChainEntry e1 = chainService.append(AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        AuditChainEntry e2 = chainService.append(AuditEventType.LOGOUT_SUCCESS,"alice", null, null, null, null, null, null);

        assertThat(e1.getSelfHash()).isNotEqualTo(e2.getSelfHash());
    }

    @Test
    @DisplayName("Entry é persistido no banco com todos os campos obrigatórios não-nulos")
    void append_Entry_HasAllRequiredFieldsNotNull() {
        AuditChainEntry entry = chainService.append(
            AuditEventType.SHIELD_REQUEST_BLOCKED, "bob",
            "jti-x", "10.0.0.1", "Mozilla/5.0", "/api/secret", "blocked", Map.of("score", 95));

        AuditChainEntry loaded = repository.findById(entry.getId()).orElseThrow();
        assertThat(loaded.getId()).isNotNull();
        assertThat(loaded.getTimestamp()).isNotNull();
        assertThat(loaded.getEventType()).isEqualTo(AuditEventType.SHIELD_REQUEST_BLOCKED);
        assertThat(loaded.getActor()).isEqualTo("bob");
        assertThat(loaded.getPreviousHash()).isNotNull();
        assertThat(loaded.getSelfHash()).isNotNull();
        assertThat(loaded.getSequenceNumber()).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Concorrência: escritas simultâneas para o mesmo ator
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("5 threads escrevendo simultaneamente para o mesmo ator produzem cadeia íntegra")
    void append_ConcurrentWritesSameActor_ProducesIntactChain() throws InterruptedException {
        int threadCount = 5;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch  = new CountDownLatch(threadCount);
        ExecutorService executor  = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            int idx = i;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    chainService.append(
                        AuditEventType.ABAC_DECISION_PERMIT, "concurrent_actor",
                        "jti-" + idx, null, null, null, "thread-" + idx, null);
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown(); // dispara todas as threads ao mesmo tempo
        assertThat(doneLatch.await(15, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        // Após todas as escritas concorrentes, a cadeia deve estar íntegra
        ChainVerificationReport report = verifier.verify("concurrent_actor");
        assertThat(report.totalEntries()).isEqualTo(threadCount);
        assertThat(report.isValid()).isTrue();

        // Sequências devem ser contíguas (1, 2, 3, 4, 5)
        List<AuditChainEntry> chain = repository.findByActorOrderBySequenceNumberAsc("concurrent_actor");
        assertThat(chain).hasSize(threadCount);
        for (int i = 0; i < chain.size(); i++) {
            assertThat(chain.get(i).getSequenceNumber()).isEqualTo(i + 1L);
        }
    }
}
