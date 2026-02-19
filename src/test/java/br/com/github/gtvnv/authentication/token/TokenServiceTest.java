package br.com.github.gtvnv.authentication.token;

import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.crypto.KeyManagerService; // 🔥 Importante: Novo Serviço
import br.com.github.gtvnv.domain.model.Subject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    // 1. Mockamos as configurações de tempo
    @Mock
    private JwtProperties jwtProperties;

    // 2. Mockamos o gerenciador de chaves (Quem entrega a RSA Key)
    @Mock
    private KeyManagerService keyManagerService;

    @InjectMocks
    private TokenService tokenService;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Gera par de chaves RSA real para o teste
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();

        // --- Configuração dos Mocks ---

        // Configura o KeyManager para retornar nossas chaves geradas agora
        // Usei 'lenient()' porque alguns testes usam só a privada, outros só a pública.
        // Isso evita o erro "UnnecessaryStubbingException" do Mockito.
        lenient().when(keyManagerService.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        lenient().when(keyManagerService.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());

        // Configura o JwtProperties para retornar os tempos de expiração
        lenient().when(jwtProperties.getAccessTokenExpiration()).thenReturn(3600L); // 1 hora (segundos)
        // O refreshTokenExpiration não é usado em todos os testes, então lenient() ajuda aqui também
        lenient().when(jwtProperties.getRefreshTokenExpiration()).thenReturn(86400L);
    }

    @Test
    @DisplayName("Deve gerar Access Token contendo a Claim 'verified' correta")
    void generateAccessToken_ShouldIncludeVerifiedClaim() {
        // Arrange
        Subject subject = new Subject("gustavo_admin", List.of("ADMIN"), Map.of(), true);

        // Act
        String token = tokenService.generateAccessToken(subject);

        // Assert
        assertNotNull(token);

        // Decodifica usando a chave pública REAL (gerada no setup)
        Claims claims = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals("gustavo_admin", claims.getSubject());
        assertEquals(true, claims.get("verified")); // Verifica o Soft Lock
        assertEquals("ACCESS", claims.get("type"));
    }

    @Test
    @DisplayName("Deve validar se o token pertence ao UserDetails correto")
    void isTokenValid_ShouldReturnTrue_WhenUserMatches() {
        // Arrange
        Subject subject = new Subject("user_teste", List.of("USER"), Map.of(), false);
        String token = tokenService.generateAccessToken(subject);

        UserDetails userDetails = User.builder()
                .username("user_teste")
                .password("password")
                .roles("USER")
                .build();

        // Act & Assert
        // O tokenService internamente chama keyManagerService.getPublicKey() para validar.
        // Como mockamos isso no setUp, vai funcionar.
        assertTrue(tokenService.isTokenValid(token, userDetails));
    }

    @Test
    @DisplayName("Deve falhar se o token for de outro usuário")
    void isTokenValid_ShouldReturnFalse_WhenUserMismatch() {
        // Arrange
        Subject subject = new Subject("hacker", List.of("USER"), Map.of(), false);
        String token = tokenService.generateAccessToken(subject);

        UserDetails userDetails = User.builder()
                .username("vitima_inocente")
                .password("password")
                .roles("USER")
                .build();

        // Act & Assert
        assertFalse(tokenService.isTokenValid(token, userDetails));
    }
}