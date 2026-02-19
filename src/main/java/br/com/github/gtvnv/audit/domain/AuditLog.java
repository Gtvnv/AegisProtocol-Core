package br.com.github.gtvnv.audit.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    private String actor; // Quem fez (User ID ou "ANONYMOUS")

    @Column(nullable = false)
    private String action; // GET, POST, DELETE

    @Column(nullable = false)
    private String resource; // /api/secret

    @Column(nullable = false)
    private String outcome; // ALLOWED ou DENIED

    @Column(columnDefinition = "TEXT")
    private String detail; // "Access denied by policy POL-001"

    private String ipAddress;
}