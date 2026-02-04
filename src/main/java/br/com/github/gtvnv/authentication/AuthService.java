package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.authentication.dto.LoginRequest;
import br.com.github.gtvnv.authentication.dto.TokenResponse;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.domain.model.Subject;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class AuthService {

    private final TokenService tokenService;
    private final JwtProperties jwtProperties;

    public AuthService(TokenService tokenService, JwtProperties jwtProperties) {
        this.tokenService = tokenService;
        this.jwtProperties = jwtProperties;
    }

    public TokenResponse login(LoginRequest request) {
        // 1. Aqui entraria a validação de senha (ex: BCrypt contra o banco)
        // Por enquanto, vamos simular que o usuário "admin" acertou a senha.
        if (!"admin".equals(request.username()) || !"123456".equals(request.password())) {
            throw new RuntimeException("Credenciais Inválidas"); // Em prod, use Exception customizada
        }

        // 2. Monta o Subject (O objeto que representa quem logou)
        // Num caso real, você buscaria as Roles no banco de dados agora.
        Subject subject = new Subject(
                "user-uuid-1234", // ID único do usuário
                List.of("ADMIN", "MANAGER"), // Roles carregadas
                Map.of("department", "IT", "region", "BR") // Atributos para ABAC
        );

        // 3. Gera os Tokens
        String accessToken = tokenService.generateAccessToken(subject);
        String refreshToken = tokenService.generateRefreshToken(subject.id());

        // 4. (TODO) Salvar o RefreshToken no Redis para permitir revogação futura
        // saveRefreshTokenToRedis(refreshToken, subject.id());

        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtProperties.getAccessTokenExpiration()
        );
    }
}