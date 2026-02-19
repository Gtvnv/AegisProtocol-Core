package br.com.github.gtvnv.domain.repository;

import br.com.github.gtvnv.domain.entity.PolicyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface PolicyRepository extends JpaRepository<PolicyEntity, UUID> {
    // Aqui podemos adicionar buscas customizadas no futuro
    // Ex: buscar todas as políticas ativas ordenadas por prioridade
}