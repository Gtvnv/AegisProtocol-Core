package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.authentication.dto.LoginRequest;
import br.com.github.gtvnv.authentication.dto.TokenResponse;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.domain.entity.UserEntity;
import br.com.github.gtvnv.domain.model.Subject;
import br.com.github.gtvnv.domain.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private TokenService tokenService;
    @Mock private JwtProperties jwtProperties;
    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private TokenBlacklistService blacklistService;

    @InjectMocks
    private AuthService authService;

    @Test
    @DisplayName("Login deve emitir token com verified=false se usuário não tiver e-mail confirmado")
    void login_ShouldIssueUnverifiedToken_WhenUserNotEnabled() {
        // 1. Arrange (Cenário)
        String username = "novo_usuario";
        LoginRequest request = new LoginRequest(username, "123456");

        // Mock do Spring Security (Autenticação passa)
        Authentication authMock = mock(Authentication.class);
        UserDetails userDetailsMock = new User(username, "hash", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(authMock.getPrincipal()).thenReturn(userDetailsMock);

        // Mock do Banco de Dados (A Verdade Real: enabled = false)
        UserEntity realUser = UserEntity.builder()
                .username(username)
                .enabled(false) // 🔥 AQUI ESTÁ O SOFT LOCK
                .roles(Set.of("USER"))
                .build();
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(realUser));

        // Mock do TokenService
        when(tokenService.generateAccessToken(any())).thenReturn("token_acesso_falso");
        when(tokenService.generateRefreshToken(any())).thenReturn("token_refresh_falso");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(1000L);

        // 2. Act (Execução)
        TokenResponse response = authService.login(request);

        // 3. Assert (Validação)
        assertNotNull(response);

        // 🔥 O PULO DO GATO: Vamos capturar o objeto Subject que foi passado para o TokenService
        // para garantir que o AuthService setou 'false' nele.
        ArgumentCaptor<Subject> subjectCaptor = ArgumentCaptor.forClass(Subject.class);
        verify(tokenService).generateAccessToken(subjectCaptor.capture());

        Subject capturedSubject = subjectCaptor.getValue();
        assertFalse(capturedSubject.isVerified(), "O Subject deve estar marcado como não verificado!");
    }
}