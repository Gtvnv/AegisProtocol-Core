package br.com.github.gtvnv.audit.chain.repository;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AuditChainRepository extends JpaRepository<AuditChainEntry, String> {

    // Usado pelo AuditChainService para obter o hash anterior antes de inserir.
    // PESSIMISTIC_WRITE garante que dois eventos simultâneos do mesmo ator
    // não leiam o mesmo "último entry" e corrompam a cadeia.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuditChainEntry> findFirstByActorOrderBySequenceNumberDesc(String actor);

    // Queries de leitura (sem lock) para o verifier e o controller
    List<AuditChainEntry> findByActorOrderBySequenceNumberAsc(String actor);

    Page<AuditChainEntry> findByActorOrderBySequenceNumberDesc(String actor, Pageable pageable);

    List<AuditChainEntry> findByEventType(AuditEventType eventType);

    @Query("SELECT DISTINCT e.actor FROM AuditChainEntry e")
    List<String> findAllDistinctActors();
}
