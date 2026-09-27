package br.com.github.gtvnv.privacy.repository;

import br.com.github.gtvnv.privacy.domain.PrivacySubjectKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PrivacySubjectKeyRepository extends JpaRepository<PrivacySubjectKey, String> {
}
