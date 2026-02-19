package br.com.github.gtvnv.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "Gustavo Ventura",
                        email = "seu.email@exemplo.com",
                        url = "https://github.com/gtvnv"
                ),
                description = "Documentação oficial da API Aegis Protocol - Identity Provider Zero Trust.",
                title = "Aegis Protocol Core API",
                version = "1.0",
                license = @License(
                        name = "MIT License",
                        url = "https://opensource.org/licenses/MIT"
                )
        ),
        servers = {
                @Server(
                        description = "Ambiente de Desenvolvimento (Local)",
                        url = "http://localhost:9090"
                )
        },
        // 🔥 Esta linha aplica a segurança JWT em TODOS os endpoints globalmente
        security = {
                @SecurityRequirement(name = "bearerAuth")
        }
)
// 🔥 Esta anotação cria o esquema de segurança (o botão verde "Authorize")
@SecurityScheme(
        name = "bearerAuth",
        description = "Cole seu token JWT aqui (apenas o token, sem 'Bearer ')",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
    // Classe vazia, as anotações fazem tudo sozinhas!
}