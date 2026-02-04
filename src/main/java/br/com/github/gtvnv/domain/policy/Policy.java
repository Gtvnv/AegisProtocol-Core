package br.com.github.gtvnv.domain.policy;

import java.util.List;

public record Policy(
        String id,
        String name,
        String description,
        Effect effect,       // PERMIT ou DENY
        Target target,       // Onde essa regra se aplica? (ex: Só na rota /financeiro)
        List<Condition> conditions, // As regras finas (ABAC)
        int priority         // Em caso de conflito, quem ganha?
) {}