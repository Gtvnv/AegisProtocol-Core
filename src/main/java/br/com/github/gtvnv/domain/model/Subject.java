package br.com.github.gtvnv.domain.model;

import java.util.List;
import java.util.Map;

// Esse é o usuário "normalizado" que viaja pelo sistema
public record Subject(
        String id,
        List<String> roles,
        Map<String, Object> attributes,
        boolean isVerified // ✅ NOVO CAMPO
) {
    // Construtor compacto para manter compatibilidade (opcional, mas útil)
    public Subject(String id, List<String> roles, Map<String, Object> attributes) {
        this(id, roles, attributes, false); // Padrão false se não informado
    }
}