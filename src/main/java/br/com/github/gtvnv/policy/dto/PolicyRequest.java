package br.com.github.gtvnv.policy.dto;

import br.com.github.gtvnv.domain.policy.Condition;
import br.com.github.gtvnv.domain.policy.Effect;
import br.com.github.gtvnv.domain.policy.Target;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record PolicyRequest(
        @NotBlank String name,
        String description,
        @NotNull Effect effect,
        int priority,
        @NotNull Target target,
        List<Condition> conditions
) {}
