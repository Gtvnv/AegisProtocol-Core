package br.com.github.gtvnv.authentication.filter;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.service.AegisUserDetailsService;
import br.com.github.gtvnv.authentication.token.TokenService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes adversariais do JwtAuthenticationFilter.
 *
 * Cenários: sem Authorization header, token na blacklist (401 imediato),
 * refresh token usado como access token (sem autenticação + evento auditado),
 * token inválido/expirado (sem autenticação), token válido (SecurityContext populado).
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock private TokenService          tokenService;
    @Mock private AegisUserDetailsService userDetailsService;
    @Mock private TokenBlacklistService  blacklistService;
    @Mock private AuditEventPublisher    chainPublisher;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    private MockHttpServletRequest  request;
    private MockHttpServletResponse response;
    private MockFilterChain         chain;

    @BeforeEach
    void setUp() {
        request  = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain    = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // -----------------------------------------------------------------------
    // Sem Authorization header
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sem header Authorization: passa para o próximo filtro sem tocar no SecurityContext")
    void filter_NoAuthorizationHeader_PassesThrough() throws Exception {
        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull(); // chain.doFilter foi chamado
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
        verifyNoInteractions(blacklistService, tokenService, userDetailsService, chainPublisher);
    }

    @Test
    @DisplayName("Header Authorization sem 'Bearer ': passa para o próximo filtro")
    void filter_AuthHeaderWithoutBearer_PassesThrough() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(blacklistService, tokenService);
    }

    // -----------------------------------------------------------------------
    // Token na blacklist
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Token revogado (blacklist): responde 401, não avança na filter chain")
    void filter_BlacklistedToken_Returns401AndStopsChain() throws Exception {
        request.addHeader("Authorization", "Bearer revoked.jwt.token");
        when(blacklistService.isTokenBlacklisted("revoked.jwt.token")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("Token revoked or expired");
    }

    @Test
    @DisplayName("Token revogado: publica TOKEN_BLACKLIST_VIOLATION com actor ANONYMOUS")
    void filter_BlacklistedToken_PublishesBlacklistViolationEvent() throws Exception {
        request.addHeader("Authorization", "Bearer revoked.jwt.token");
        when(blacklistService.isTokenBlacklisted("revoked.jwt.token")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        verify(chainPublisher).publishTokenEvent(
            eq(AuditEventType.TOKEN_BLACKLIST_VIOLATION),
            eq("ANONYMOUS"), isNull(), any());
    }

    @Test
    @DisplayName("Token revogado: tokenService.validateAndGetClaims nunca é chamado (fast-fail real)")
    void filter_BlacklistedToken_NeverCallsValidateClaims() throws Exception {
        request.addHeader("Authorization", "Bearer revoked.jwt.token");
        when(blacklistService.isTokenBlacklisted("revoked.jwt.token")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        verify(tokenService, never()).validateAndGetClaims(any());
    }

    // -----------------------------------------------------------------------
    // Token inválido ou expirado
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Token com assinatura inválida: passa para o próximo filtro sem autenticar")
    void filter_InvalidSignature_PassesThroughWithoutAuthenticating() throws Exception {
        request.addHeader("Authorization", "Bearer invalid.jwt.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);
        when(tokenService.validateAndGetClaims(any()))
            .thenThrow(new io.jsonwebtoken.security.SignatureException("Invalid signature"));

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull(); // chain avançou
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isEqualTo(200); // sem 401 (Spring Security decide depois)
    }

    @Test
    @DisplayName("Token expirado: passa para o próximo filtro sem autenticar")
    void filter_ExpiredToken_PassesThroughWithoutAuthenticating() throws Exception {
        request.addHeader("Authorization", "Bearer expired.jwt.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);
        when(tokenService.validateAndGetClaims(any()))
            .thenThrow(new io.jsonwebtoken.ExpiredJwtException(null, null, "Token expired"));

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    // -----------------------------------------------------------------------
    // Refresh token usado como access token
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Refresh token como access: passa para o próximo filtro SEM popular SecurityContext")
    void filter_RefreshTokenUsedAsAccess_DoesNotAuthenticate() throws Exception {
        request.addHeader("Authorization", "Bearer refresh.jwt.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);

        Claims claims = mockClaims("alice", "jti-r", "REFRESH"); // type = REFRESH, não ACCESS
        when(tokenService.validateAndGetClaims(any())).thenReturn(claims);

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull(); // chain avançou (não bloqueado)
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(userDetailsService, never()).loadUserByUsername(any());
    }

    @Test
    @DisplayName("Refresh token como access: publica REFRESH_TOKEN_USED_AS_ACCESS com actor correto")
    void filter_RefreshTokenUsedAsAccess_PublishesEvent() throws Exception {
        request.addHeader("Authorization", "Bearer refresh.jwt.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);

        Claims claims = mockClaims("alice", "jti-r", "REFRESH");
        when(tokenService.validateAndGetClaims(any())).thenReturn(claims);

        filter.doFilter(request, response, chain);

        verify(chainPublisher).publishTokenEvent(
            eq(AuditEventType.REFRESH_TOKEN_USED_AS_ACCESS),
            eq("alice"), eq("jti-r"), any());
    }

    // -----------------------------------------------------------------------
    // Token válido (caminho feliz)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Token de acesso válido: SecurityContext é populado com o usuário correto")
    void filter_ValidAccessToken_PopulatesSecurityContext() throws Exception {
        request.addHeader("Authorization", "Bearer valid.access.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);

        Claims claims = mockClaims("alice", "jti-a", "ACCESS");
        when(tokenService.validateAndGetClaims(any())).thenReturn(claims);

        UserDetails userDetails = new User("alice", "hash",
            List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(userDetails);
        when(tokenService.isTokenValid(any(), eq(userDetails))).thenReturn(true);

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
            .isEqualTo("alice");
    }

    @Test
    @DisplayName("Token válido mas isTokenValid retorna false: SecurityContext permanece vazio")
    void filter_ValidTokenButUserMismatch_DoesNotAuthenticate() throws Exception {
        request.addHeader("Authorization", "Bearer mismatched.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);

        Claims claims = mockClaims("alice", "jti-a", "ACCESS");
        when(tokenService.validateAndGetClaims(any())).thenReturn(claims);

        UserDetails userDetails = new User("alice", "hash", List.of());
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(userDetails);
        when(tokenService.isTokenValid(any(), eq(userDetails))).thenReturn(false);

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Token válido: nenhum evento de auditoria negativo é publicado")
    void filter_ValidAccessToken_NoNegativeAuditEvents() throws Exception {
        request.addHeader("Authorization", "Bearer valid.access.token");
        when(blacklistService.isTokenBlacklisted(any())).thenReturn(false);

        Claims claims = mockClaims("alice", "jti-a", "ACCESS");
        when(tokenService.validateAndGetClaims(any())).thenReturn(claims);

        UserDetails userDetails = new User("alice", "hash",
            List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(userDetails);
        when(tokenService.isTokenValid(any(), eq(userDetails))).thenReturn(true);

        filter.doFilter(request, response, chain);

        verify(chainPublisher, never()).publishTokenEvent(
            eq(AuditEventType.TOKEN_BLACKLIST_VIOLATION), any(), any(), any());
        verify(chainPublisher, never()).publishTokenEvent(
            eq(AuditEventType.REFRESH_TOKEN_USED_AS_ACCESS), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private Claims mockClaims(String subject, String jti, String type) {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(subject);
        when(claims.getId()).thenReturn(jti);
        when(claims.get("type", String.class)).thenReturn(type);
        return claims;
    }
}
