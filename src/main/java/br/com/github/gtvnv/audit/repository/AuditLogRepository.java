package br.com.github.gtvnv.audit.repository;

import br.com.github.gtvnv.audit.domain.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    // Busca todos os logs de um usuário específico (ex: "O que o admin fez hoje?")
    List<AuditLog> findByActor(String actor);

    // Busca acessos a um recurso específico (ex: "Quem tentou acessar /api/secret?")
    List<AuditLog> findByResource(String resource);

    // Busca logs por status (ex: "Quais foram os acessos NEGADOS?")
    List<AuditLog> findByOutcome(String outcome);

    // Busca logs em um intervalo de tempo (Essencial para auditoria forense)
    List<AuditLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);
}