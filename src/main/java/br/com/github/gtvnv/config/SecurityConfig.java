package br.com.github.gtvnv.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // 1. Desabilita CSRF (Essencial para APIs REST, pois não usamos sessão de browser)
                .csrf(AbstractHttpConfigurer::disable)

                // 2. Define que a API é STATELESS (Não guarda estado/session no servidor)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 3. O Guardião das Rotas
                .authorizeHttpRequests(authorize -> authorize
                        // Libera o Login (Porta da Frente)
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        // Libera Swagger/OpenAPI (Opcional, se você for usar depois)
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()

                        // BLOQUEIA O RESTO (Zero Trust: "Authorize any request? Authenticated!")
                        .anyRequest().authenticated()
                )
                .build();
    }
}