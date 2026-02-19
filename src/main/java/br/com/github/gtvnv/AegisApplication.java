package br.com.github.gtvnv;

import br.com.github.gtvnv.domain.policy.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.List;

@EnableAsync
@SpringBootApplication
public class AegisApplication {

    public static void main(String[] args) {
        SpringApplication.run(AegisApplication.class, args);
    }

    @Bean
    public List<Policy> initialPolicies() {
        Policy allowSecretPolicy = new Policy(
                "POL-001",
                "Permitir Acesso ao Secret",
                "Libera acesso GET na rota secret para ADMINs",
                Effect.PERMIT,
                new Target(List.of("/api/secret"), List.of("GET")), // Target: Rota exata
                List.of(
                        new Condition("subject.roles", Operator.CONTAINS, "ADMIN") // Só ADMIN passa
                ),
                1
        );
        return List.of(allowSecretPolicy);
    }

}
