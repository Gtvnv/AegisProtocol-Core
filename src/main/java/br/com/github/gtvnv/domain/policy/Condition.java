package br.com.github.gtvnv.domain.policy;

// Condition é a lógica dinâmica (ex: "amount < 10000" ou "time is working_hours")
public record Condition(
        String attribute,  // ex: "subject.attributes.department"
        Operator operator, // ex: EQUALS, GREATER_THAN, IN
        String value       // ex: "FINANCE"
) {}