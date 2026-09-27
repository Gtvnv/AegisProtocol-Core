package br.com.github.gtvnv.retention.repository;

import br.com.github.gtvnv.retention.domain.RetentionCheckpoint;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RetentionCheckpointRepository extends JpaRepository<RetentionCheckpoint, UUID> {

    // Ponto de retomada: de onde continuar arquivando este ator.
    Optional<RetentionCheckpoint> findFirstByActorOrderByToSequenceDesc(String actor);

    List<RetentionCheckpoint> findAllByOrderByCreatedAtDesc();
}
