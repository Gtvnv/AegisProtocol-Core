package br.com.github.gtvnv.network.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Uma faixa de rede confiável (CIDR IPv4). Ex: name="vpc-interna",
 * cidr="10.0.0.0/8" — origens fora de nenhuma zona habilitada são tratadas
 * como não confiáveis pelo NetworkSentinelFilter nos caminhos protegidos.
 */
@Entity
@Table(name = "network_zones")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkZone {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private String cidr;

    private String description;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false)
    private Instant createdAt;
}
