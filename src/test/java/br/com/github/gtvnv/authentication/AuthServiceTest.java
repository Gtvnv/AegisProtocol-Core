package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.authentication.dto.LoginRequest;
import br.com.github.gtvnv.authentication.dto.RegisterRequest;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes adversariais do AuthService.
 *
 * Cobre: soft lock (verified=false), credenciais inválidas,
 * username duplicado, refresh com token revogado, refresh com access token,
 * refresh de usuário deletado, refresh de conta desativada,
 * rotação de refresh token (token antigo é blacklistado).
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private TokenService          tokenService;
    @Mock private JwtProperties         jwtProperties;
    @Mock private UserRepository        userRepository;
    @Mock private PasswordEncoder       passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private TokenBlacklistService tokenBlacklistService;
    @Mock private AuditEventPublisher   chainPublisher;

    @InjectMocks
    private AuthService authService;

    // -----------------------------------------------------------------------
    // login — soft lock
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Login de usuário não verificado retorna Subject com verified=false")
    void login_UnverifiedUser_SubjectHasVerifiedFalse() {
        Authentication authMock = mockAuthentication("novo_usuario", List.of("USER"));
        UserEntity entity = userEntity("novo_usuario", false, Set.of("USER"));

        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(userRepository.findByUsername("novo_usuario")).thenReturn(Optional.of(entity));
        when(tokenService.generateAccessToken(any())).thenReturn("access_token");
        when(tokenService.generateRefreshToken(any())).thenReturn("refresh_token");
        when(tokenService.extractJti(any())).thenReturn("jti_abc");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.login(new LoginRequest("novo_usuario", "pass"));

        ArgumentCaptor<Subject> captor = ArgumentCaptor.forClass(Subject.class);
        verify(tokenService).generateAccessToken(captor.capture());
        assertThat(captor.getValue().isVerified()).isFalse();
    }

    @Test
    @DisplayName("Login de usuário verificado retorna Subject com verified=true")
    void login_VerifiedUser_SubjectHasVerifiedTrue() {
        Authentication authMock = mockAuthentication("admin", List.of("ADMIN"));
        UserEntity entity = userEntity("admin", true, Set.of("ADMIN"));

        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(entity));
        when(tokenService.generateAccessToken(any())).thenReturn("access_token");
        when(tokenService.generateRefreshToken(any())).thenReturn("refresh_token");
        when(tokenService.extractJti(any())).thenReturn("jti_xyz");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.login(new LoginRequest("admin", "pass"));

        ArgumentCaptor<Subject> captor = ArgumentCaptor.forClass(Subject.class);
        verify(tokenService).generateAccessToken(captor.capture());
        assertThat(captor.getValue().isVerified()).isTrue();
    }

    @Test
    @DisplayName("Login bem-sucedido publica LOGIN_SUCCESS, TOKEN_ISSUED e REFRESH_TOKEN_ISSUED")
    void login_Success_PublishesThreeChainEvents() {
        Authentication authMock = mockAuthentication("alice", List.of("USER"));
        UserEntity entity = userEntity("alice", true, Set.of("USER"));

        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(entity));
        when(tokenService.generateAccessToken(any())).thenReturn("at");
        when(tokenService.generateRefreshToken(any())).thenReturn("rt");
        when(tokenService.extractJti(any())).thenReturn("jti1");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.login(new LoginRequest("alice", "pass"));

        verify(chainPublisher).publishAuthEvent(
            eq(AuditEventType.LOGIN_SUCCESS), eq("alice"), any(), any(), any());
        verify(chainPublisher).publishTokenEvent(
            eq(AuditEventType.TOKEN_ISSUED), eq("alice"), any(), any());
        verify(chainPublisher).publishTokenEvent(
            eq(AuditEventType.REFRESH_TOKEN_ISSUED), eq("alice"), any(), any());
    }

    // -----------------------------------------------------------------------
    // login — credenciais inválidas
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Credenciais inválidas: exceção é relançada e LOGIN_FAILURE é publicado")
    void login_BadCredentials_ThrowsAndPublishesLoginFailure() {
        when(authenticationManager.authenticate(any()))
            .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(new LoginRequest("hacker", "wrong")))
            .isInstanceOf(BadCredentialsException.class);

        verify(chainPublisher).publishAuthEvent(
            eq(AuditEventType.LOGIN_FAILURE), eq("hacker"), any(), isNull(), any());
        verify(tokenService, never()).generateAccessToken(any());
    }

    @Test
    @DisplayName("Exceção genérica no AuthenticationManager: também publica LOGIN_FAILURE")
    void login_GenericAuthException_PublishesLoginFailure() {
        when(authenticationManager.authenticate(any()))
            .thenThrow(new RuntimeException("service unavailable"));

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "pass")))
            .isInstanceOf(RuntimeException.class);

        verify(chainPublisher).publishAuthEvent(
            eq(AuditEventType.LOGIN_FAILURE), eq("alice"), any(), isNull(), any());
    }

    // -----------------------------------------------------------------------
    // register
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Register com username já existente lança IllegalArgumentException")
    void register_DuplicateUsername_ThrowsIllegalArgument() {
        when(userRepository.existsByUsername("alice")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(
            new RegisterRequest("alice", "pass123!", "alice@test.com", Set.of("USER"))))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Username already exists");

        verify(userRepository, never()).save(any());
        verify(chainPublisher, never()).publishAuthEvent(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Register novo usuário publica ACCOUNT_CREATED e depois faz login")
    void register_NewUser_PublishesAccountCreatedThenLogin() {
        when(userRepository.existsByUsername("bob")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hashed_pass");
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        // Setup para o login subsequente dentro do register
        Authentication authMock = mockAuthentication("bob", List.of("USER"));
        UserEntity entity = userEntity("bob", false, Set.of("USER"));
        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(entity));
        when(tokenService.generateAccessToken(any())).thenReturn("at");
        when(tokenService.generateRefreshToken(any())).thenReturn("rt");
        when(tokenService.extractJti(any())).thenReturn("jti1");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.register(new RegisterRequest("bob", "pass123!", "bob@test.com", Set.of("USER")));

        verify(chainPublisher).publishAuthEvent(
            eq(AuditEventType.ACCOUNT_CREATED), eq("bob"), any(), isNull(), any());
    }

    @Test
    @DisplayName("Register sem roles usa 'USER' como padrão")
    void register_NullRoles_DefaultsToUser() {
        when(userRepository.existsByUsername("carlos")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");

        ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
        when(userRepository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        // Precisamos mockar tudo para o login interno não falhar
        Authentication authMock = mockAuthentication("carlos", List.of("USER"));
        UserEntity entity = userEntity("carlos", false, Set.of("USER"));
        when(authenticationManager.authenticate(any())).thenReturn(authMock);
        when(userRepository.findByUsername("carlos")).thenReturn(Optional.of(entity));
        when(tokenService.generateAccessToken(any())).thenReturn("at");
        when(tokenService.generateRefreshToken(any())).thenReturn("rt");
        when(tokenService.extractJti(any())).thenReturn("jti1");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.register(new RegisterRequest("carlos", "pass!", "c@test.com", null));

        assertThat(captor.getValue().getRoles()).containsExactly("USER");
    }

    // -----------------------------------------------------------------------
    // refreshToken
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("refreshToken com header inválido (sem 'Bearer ') lança IllegalArgumentException")
    void refreshToken_InvalidHeader_ThrowsIllegalArgument() {
        assertThatThrownBy(() -> authService.refreshToken("invalid_token_without_bearer"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Token inválido");
    }

    @Test
    @DisplayName("refreshToken com header null lança IllegalArgumentException")
    void refreshToken_NullHeader_ThrowsIllegalArgument() {
        assertThatThrownBy(() -> authService.refreshToken(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("refreshToken com token na blacklist lança SecurityException")
    void refreshToken_BlacklistedToken_ThrowsSecurityException() {
        when(tokenBlacklistService.isTokenBlacklisted("revoked.token.here")).thenReturn(true);

        assertThatThrownBy(() -> authService.refreshToken("Bearer revoked.token.here"))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("revogado");
    }

    @Test
    @DisplayName("refreshToken com access token (não é refresh) lança IllegalArgumentException")
    void refreshToken_AccessTokenUsedAsRefresh_ThrowsIllegalArgument() {
        String accessToken = "access.token.here";
        when(tokenBlacklistService.isTokenBlacklisted(accessToken)).thenReturn(false);
        when(tokenService.validateAndGetClaims(accessToken)).thenReturn(null);
        when(tokenService.isRefreshToken(accessToken)).thenReturn(false);

        assertThatThrownBy(() -> authService.refreshToken("Bearer " + accessToken))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Refresh Token");
    }

    @Test
    @DisplayName("refreshToken com usuário deletado lança RuntimeException")
    void refreshToken_DeletedUser_ThrowsRuntimeException() {
        String refreshToken = "valid.refresh.token";
        when(tokenBlacklistService.isTokenBlacklisted(refreshToken)).thenReturn(false);
        when(tokenService.validateAndGetClaims(refreshToken)).thenReturn(null);
        when(tokenService.isRefreshToken(refreshToken)).thenReturn(true);
        when(tokenService.extractUsername(refreshToken)).thenReturn("ghost_user");
        when(userRepository.findByUsername("ghost_user")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken("Bearer " + refreshToken))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("não existe");
    }

    @Test
    @DisplayName("refreshToken com conta desativada (enabled=false, verificado no banco) lança SecurityException")
    void refreshToken_DisabledAccount_ThrowsSecurityException() {
        String refreshToken = "valid.refresh.token";
        UserEntity disabledUser = userEntity("dave", false, Set.of("USER"));
        disabledUser.setEnabled(false); // conta explicitamente desativada

        when(tokenBlacklistService.isTokenBlacklisted(refreshToken)).thenReturn(false);
        when(tokenService.validateAndGetClaims(refreshToken)).thenReturn(null);
        when(tokenService.isRefreshToken(refreshToken)).thenReturn(true);
        when(tokenService.extractUsername(refreshToken)).thenReturn("dave");
        when(userRepository.findByUsername("dave")).thenReturn(Optional.of(disabledUser));

        assertThatThrownBy(() -> authService.refreshToken("Bearer " + refreshToken))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("desativada");
    }

    @Test
    @DisplayName("refreshToken válido: token antigo é adicionado à blacklist (refresh rotation)")
    void refreshToken_ValidToken_OldTokenIsBlacklisted() {
        String oldRefreshToken = "old.refresh.token";
        UserEntity enabledUser = userEntity("eve", true, Set.of("USER"));

        when(tokenBlacklistService.isTokenBlacklisted(oldRefreshToken)).thenReturn(false);
        when(tokenService.validateAndGetClaims(oldRefreshToken)).thenReturn(null);
        when(tokenService.isRefreshToken(oldRefreshToken)).thenReturn(true);
        when(tokenService.extractUsername(oldRefreshToken)).thenReturn("eve");
        when(userRepository.findByUsername("eve")).thenReturn(Optional.of(enabledUser));
        when(tokenService.extractExpiration(oldRefreshToken))
            .thenReturn(new Date(System.currentTimeMillis() + 3600_000L));
        when(tokenService.generateAccessToken(any())).thenReturn("new_access");
        when(tokenService.generateRefreshToken(any())).thenReturn("new_refresh");
        when(tokenService.extractJti(any())).thenReturn("new_jti");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        authService.refreshToken("Bearer " + oldRefreshToken);

        verify(tokenBlacklistService).blacklistToken(eq(oldRefreshToken), anyLong());
    }

    @Test
    @DisplayName("refreshToken válido retorna novos tokens e publica TOKEN_REFRESHED + REFRESH_TOKEN_ISSUED")
    void refreshToken_ValidToken_ReturnsNewTokensAndPublishesEvents() {
        String oldToken = "old.refresh.token";
        UserEntity user = userEntity("eve", true, Set.of("USER"));

        when(tokenBlacklistService.isTokenBlacklisted(oldToken)).thenReturn(false);
        when(tokenService.validateAndGetClaims(oldToken)).thenReturn(null);
        when(tokenService.isRefreshToken(oldToken)).thenReturn(true);
        when(tokenService.extractUsername(oldToken)).thenReturn("eve");
        when(userRepository.findByUsername("eve")).thenReturn(Optional.of(user));
        when(tokenService.extractExpiration(oldToken))
            .thenReturn(new Date(System.currentTimeMillis() + 3600_000L));
        when(tokenService.generateAccessToken(any())).thenReturn("new_access");
        when(tokenService.generateRefreshToken(any())).thenReturn("new_refresh");
        when(tokenService.extractJti(any())).thenReturn("jti_new");
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(300L);

        TokenResponse response = authService.refreshToken("Bearer " + oldToken);

        assertThat(response.accessToken()).isEqualTo("new_access");
        assertThat(response.refreshToken()).isEqualTo("new_refresh");
        verify(chainPublisher).publishTokenEvent(eq(AuditEventType.TOKEN_REFRESHED),
            eq("eve"), any(), any());
        verify(chainPublisher).publishTokenEvent(eq(AuditEventType.REFRESH_TOKEN_ISSUED),
            eq("eve"), any(), any());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private Authentication mockAuthentication(String username, List<String> roles) {
        Authentication auth = mock(Authentication.class);
        List<SimpleGrantedAuthority> authorities = roles.stream()
            .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
            .toList();
        UserDetails ud = new User(username, "hash", authorities);
        when(auth.getPrincipal()).thenReturn(ud);
        return auth;
    }

    private UserEntity userEntity(String username, boolean enabled, Set<String> roles) {
        UserEntity e = UserEntity.builder()
            .username(username)
            .email(username + "@test.com")
            .password("hash")
            .enabled(enabled)
            .roles(roles)
            .build();
        return e;
    }
}
