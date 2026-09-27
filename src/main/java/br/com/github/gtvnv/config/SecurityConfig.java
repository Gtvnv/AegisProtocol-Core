package br.com.github.gtvnv.config;

import br.com.github.gtvnv.authentication.filter.JwtAuthenticationFilter;
import br.com.github.gtvnv.network.config.NetworkProperties;
import br.com.github.gtvnv.network.filter.NetworkSentinelFilter;
import br.com.github.gtvnv.shield.filter.ShieldFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ShieldFilter shieldFilter;
    private final NetworkSentinelFilter networkSentinelFilter;
    private final NetworkProperties networkProperties;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          ShieldFilter shieldFilter,
                          NetworkSentinelFilter networkSentinelFilter,
                          NetworkProperties networkProperties) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.shieldFilter = shieldFilter;
        this.networkSentinelFilter = networkSentinelFilter;
        this.networkProperties = networkProperties;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 🔥 Mantenha este Bean! Ele é a garantia que o Swagger não será interceptado
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(
                "/swagger-ui/**",
                "/v3/api-docs/**",
                "/swagger-ui.html",
                "/webjars/**" // Adicionado: Versões antigas do SpringDoc usam muito webjars
        );
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Satélite Network Sentinel: configurável por ambiente (aegis.network.cors-allowed-origins),
        // não mais hardcoded em localhost — pré-requisito pra operar como IdP entre sistemas internos reais.
        configuration.setAllowedOrigins(networkProperties.getCorsAllowedOrigins());
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // CSRF: Ignoramos Auth E Swagger (para garantir que o 'Try it out' funcione)
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers(
                                "/auth/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**"
                        )
                )

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentTypeOptions(cto -> {})
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000)
                        )
                        .contentSecurityPolicy(csp ->
                                csp.policyDirectives("default-src 'self'; frame-ancestors 'none'; object-src 'none'")
                        )
                )

                .authorizeHttpRequests(authorize -> authorize
                        // 1. Endpoints Públicos de Autenticação
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register", "/auth/refresh", "/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/auth/public-key", "/auth/public-keys",
                                "/auth/consent/current-version").permitAll()

                        // 2. Swagger (Recolocado aqui por segurança extra)
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/webjars/**"
                        ).permitAll()

                        // 3. Endpoints Administrativos
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // 4. Todo o resto exige token
                        .anyRequest().authenticated()
                )

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Network Sentinel roda antes do JWT: rejeita origem de rede não confiável
                // em /api/admin/** antes até de gastar ciclo com autenticação/ABAC (defesa em profundidade).
                .addFilterBefore(networkSentinelFilter, JwtAuthenticationFilter.class)
                .addFilterAfter(shieldFilter, JwtAuthenticationFilter.class)
                .build();
    }
}