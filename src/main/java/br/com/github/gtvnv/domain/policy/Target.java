package br.com.github.gtvnv.domain.policy;

import java.util.List;

// Target define o escopo macro (ex: Recurso = "ACCOUNT", Action = "TRANSFER")
public record Target(
        List<String> resources,
        List<String> actions
) {}
