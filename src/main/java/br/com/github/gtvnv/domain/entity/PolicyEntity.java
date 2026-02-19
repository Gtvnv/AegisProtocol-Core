package br.com.github.gtvnv.domain.entity;

import br.com.github.gtvnv.domain.policy.Condition;
import br.com.github.gtvnv.domain.policy.Effect;
import br.com.github.gtvnv.domain.policy.Policy;
import br.com.github.gtvnv.domain.policy.Target;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "policies")
@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor // Obrigatório para o JPA/Hibernate
@AllArgsConstructor // Obrigatório para o @Builder funcionar junto com o NoArgs
public class PolicyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Effect effect; // PERMIT ou DENY

    @Column(nullable = false)
    private int priority;

    // --- A MÁGICA DO JSONB ---

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Target target;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private List<Condition> conditions;

    // Método auxiliar para converter Entity -> Domain Record (usado na Engine)
    public Policy toDomain() {
        return new Policy(
                this.id != null ? this.id.toString() : null,
                this.name,
                this.description,
                this.effect,
                this.target,
                this.conditions,
                this.priority
        );
    }
}