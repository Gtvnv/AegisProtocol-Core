package br.com.github.gtvnv.domain.model;

// O contexto completo da requisição para análise
public record AccessContext(
        Subject subject,
        Resource resource,
        String action, // READ, WRITE, APPROVE
        Environment environment
) {}