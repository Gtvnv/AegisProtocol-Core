package br.com.github.gtvnv.consent.repository;

import br.com.github.gtvnv.consent.domain.ConsentRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ConsentRecordRepository extends JpaRepository<ConsentRecord, UUID> {

    Optional<ConsentRecord> findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc(String subjectId);

    void deleteBySubjectId(String subjectId);
}
