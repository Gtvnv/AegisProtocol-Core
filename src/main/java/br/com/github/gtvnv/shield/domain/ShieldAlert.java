package br.com.github.gtvnv.shield.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "shield_alerts")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ShieldAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ThreatLevel severity;

    @Column(nullable = false)
    private String alertType;

    private String actor;
    private String sessionJti;
    private String ipAddress;
    private String userAgent;
    private String resourcePath;

    @Column(nullable = false)
    private int riskScore;

    @Column(columnDefinition = "TEXT")
    private String description;
}
