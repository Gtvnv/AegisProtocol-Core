package br.com.github.gtvnv.config;

import br.com.github.gtvnv.domain.entity.PolicyEntity;
import br.com.github.gtvnv.domain.policy.Condition;
import br.com.github.gtvnv.domain.policy.Effect;
import br.com.github.gtvnv.domain.policy.Operator;
import br.com.github.gtvnv.domain.policy.Target;
import br.com.github.gtvnv.domain.repository.PolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner initDatabase(PolicyRepository repository) {
        return args -> {
            if (repository.count() == 0) {
                log.info("🌱 Banco vazio! Criando política padrão de ADMIN...");

                PolicyEntity adminPolicy = PolicyEntity.builder()
                        .name("Allow Secret Access")
                        .description("Permite acesso GET na rota secret para ADMINs")
                        .effect(Effect.PERMIT)
                        .priority(1)
                        .target(new Target(List.of("/api/secret"), List.of("GET"))) // JSONB
                        .conditions(List.of(
                                new Condition("subject.roles", Operator.CONTAINS, "ADMIN") // JSONB
                        ))
                        .build();

                repository.save(adminPolicy);
                log.info("✅ Política criada com ID: {}", adminPolicy.getId());
            }
        };
    }
}