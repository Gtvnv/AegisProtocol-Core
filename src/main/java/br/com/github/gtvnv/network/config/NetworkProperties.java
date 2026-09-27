package br.com.github.gtvnv.network.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Satélite Network Sentinel — extensão do Zero Trust do S.H.I.E.L.D. (que
 * olha sessão/comportamento) para o perímetro de rede: só fontes em zonas
 * cadastradas podem bater nos caminhos protegidos, mesmo com JWT válido e
 * role ADMIN (defesa em profundidade). Fecha ISO A.8.20 e substitui o CORS
 * hardcoded em localhost do SecurityConfig por algo configurável por ambiente.
 *
 * Fail-open de propósito quando não há nenhuma zona cadastrada: uma feature
 * nova de segurança não deve travar acesso admin por configuração ausente —
 * o filtro fica efetivamente inerte (WARN no log) até alguém cadastrar pelo
 * menos uma zona confiável.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.network")
public class NetworkProperties {
    private boolean sentinelEnabled = true;
    private List<String> protectedPathPatterns = List.of("/api/admin/**");
    private boolean blockOnUntrustedSource = false; // alerta primeiro, bloqueia só quando ligado explicitamente
    private List<String> corsAllowedOrigins = List.of("http://localhost:4200", "http://localhost:3000");
}
