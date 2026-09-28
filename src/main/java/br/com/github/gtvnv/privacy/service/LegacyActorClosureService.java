package br.com.github.gtvnv.privacy.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Satélite PrivacyGate — fecha a lacuna deixada pelo IAM Self-Service (PR #3):
 * entries gravadas ANTES do PrivacyGate existir carregam o username em claro
 * como 'actor' para sempre — nada as pseudonimiza retroativamente, porque
 * reescrever 'actor' quebraria o selfHash de toda a cadeia do ator (WORM).
 *
 * O que dá pra fazer sem violar o WORM: acrescentar UM entry final —
 * LEGACY_ACTOR_CLOSED — à cadeia em claro de cada titular legado, registrando
 * que a partir dali o titular passa a ser rastreado pelo pseudônimo. É um
 * "selo de migração" auditável, não um apagamento: as entries antigas
 * continuam com o username em claro, exatamente como o WORM exige.
 *
 * Elegibilidade espelha br.com.github.gtvnv.audit.chain.listener.ChainAuditListener:
 * mesma exclusão de "ANONYMOUS" e da categoria THREAT (actor = IP, não
 * identidade — pseudonimizar um IP não faz sentido). Idempotente: um ator já
 * encerrado (última entry = LEGACY_ACTOR_CLOSED) é pulado em reexecuções.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LegacyActorClosureService {

    private static final String PSEUDONYM_PREFIX = "anon_";
    private static final String ANONYMOUS_ACTOR = "ANONYMOUS";
    private static final String THREAT_CATEGORY = "THREAT";

    private final AuditChainRepository chainRepository;
    private final AuditChainService chainService;
    private final PrivacyGateService privacyGate;
    private final ObjectMapper objectMapper;

    public record ClosureResult(int actorsClosed, int actorsAlreadyClosed, int actorsSkippedNotIdentity) {}

    public ClosureResult runClosure() {
        int closed = 0;
        int alreadyClosed = 0;
        int skipped = 0;

        for (String actor : chainRepository.findAllDistinctActors()) {
            List<AuditChainEntry> entries = chainRepository.findByActorOrderBySequenceNumberAsc(actor);
            if (!isLegacyIdentityActor(actor, entries)) {
                skipped++;
                continue;
            }
            if (isAlreadyClosed(entries)) {
                alreadyClosed++;
                continue;
            }
            closeActor(actor);
            closed++;
        }

        log.info("PrivacyGate: encerramento de cadeias legadas — {} encerrada(s), {} já encerrada(s), {} fora do escopo.",
                closed, alreadyClosed, skipped);
        return new ClosureResult(closed, alreadyClosed, skipped);
    }

    private boolean isLegacyIdentityActor(String actor, List<AuditChainEntry> entries) {
        if (actor == null || actor.isBlank() || entries.isEmpty()) {
            return false;
        }
        if (ANONYMOUS_ACTOR.equals(actor) || actor.startsWith(PSEUDONYM_PREFIX)) {
            return false;
        }
        // Categoria vem do payload da PRIMEIRA entry — é onde o actor foi
        // definido pela primeira vez, e um actor não muda de "tipo" (IP vs.
        // identidade) ao longo da própria cadeia.
        return !THREAT_CATEGORY.equals(eventCategoryOf(entries.get(0)));
    }

    private boolean isAlreadyClosed(List<AuditChainEntry> entries) {
        AuditChainEntry last = entries.get(entries.size() - 1);
        return last.getEventType() == AuditEventType.LEGACY_ACTOR_CLOSED;
    }

    private void closeActor(String actor) {
        // get-or-create: garante que o titular já tem um pseudônimo definido
        // a partir de agora, mesmo que ainda não tenha logado desde o PrivacyGate.
        String pseudonym = privacyGate.pseudonymize(actor);

        // Chamada DIRETA a AuditChainService — nunca via AuditEventPublisher/
        // ChainAuditListener, que pseudonimizaria o actor de novo e faria este
        // entry cair na cadeia do pseudônimo em vez de encerrar a cadeia legada.
        chainService.append(
                AuditEventType.LEGACY_ACTOR_CLOSED,
                actor,
                null,
                null,
                null,
                null,
                "Legacy plaintext-actor chain superseded by PrivacyGate pseudonym for this subject going forward",
                Map.of("eventCategory", "PRIVACY", "supersededByPseudonym", pseudonym)
        );
        log.warn("PrivacyGate: cadeia legada em claro encerrada — actor='{}' sucedida por pseudônimo.", actor);
    }

    private String eventCategoryOf(AuditChainEntry entry) {
        try {
            JsonNode node = objectMapper.readTree(entry.getPayloadJson());
            JsonNode category = node.get("eventCategory");
            return category != null ? category.asText(null) : null;
        } catch (Exception e) {
            // Payload ilegível: fail-safe a favor da privacidade — trata como
            // identidade (não-THREAT) em vez de arriscar deixar um titular de fora.
            return null;
        }
    }
}
