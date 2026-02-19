package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.authentication.dto.LoginRequest;
import br.com.github.gtvnv.authentication.dto.RegisterRequest;
import br.com.github.gtvnv.authentication.dto.TokenResponse;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.domain.entity.UserEntity;
import br.com.github.gtvnv.domain.model.Subject;
import br.com.github.gtvnv.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final TokenService tokenService;
    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;
    private final AuthenticationManager authenticationManager;


    public TokenResponse login(LoginRequest request) {
        log.info("Tentativa de login para usuário: {}", request.username());

        // 1. O Spring valida a senha.
        // Como configuramos .disabled(false) no UserDetails, ele VAI passar se a senha estiver certa.
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );
        UserDetails userDetails = (UserDetails) authenticate.getPrincipal();
        // 2. 🔥 BUSCA A VERDADE REAL NO BANCO
        // Não confiamos no 'userDetails.isEnabled()' pois forçamos ele a ser true para logar.
        // Buscamos a entidade para ver o status real do campo 'enabled' (verificação de email).
        UserEntity userEntity = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Inconsistência: Usuário autenticado não encontrado no banco via AuthService."));
        // Agora sim temos o valor correto do banco (que será FALSE para novos usuários)
        boolean isEmailVerified = userEntity.isEnabled();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.replace("ROLE_", ""))
                .toList();
        // 3. Monta o Subject com o dado REAL
        Subject subject = new Subject(
                userEntity.getUsername(), // Melhor pegar da entity garantida
                roles,
                Map.of("source", "database"),
                isEmailVerified // ✅ Vai ser 'false' para recém cadastrados
        );
        String accessToken = tokenService.generateAccessToken(subject);
        String refreshToken = tokenService.generateRefreshToken(subject.id());
        log.info("Login realizado. Verified Status: {}", isEmailVerified);
        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtProperties.getAccessTokenExpiration()
        );
    }

    public TokenResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Cria o usuário.
        // Por padrão (no UserEntity), 'enabled' é false.
        UserEntity newUser = UserEntity.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(request.roles() != null ? request.roles() : Set.of("USER"))
                // .enabled(false) // Já é o padrão, mas vale reforçar mentalmente
                .build();

        userRepository.save(newUser);

        // Chama o login. Graças ao AegisUserDetailsService.disabled(false), o login funciona.
        // Graças à busca extra no login(), o token sai com "verified": false.
        return login(new LoginRequest(request.username(), request.password()));
    }

    public TokenResponse refreshToken(String refreshTokenHeader) {
        // 1. Sanitize
        if (refreshTokenHeader == null || !refreshTokenHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Token inválido");
        }
        String token = refreshTokenHeader.substring(7);

        // 2. Validações Prévias
        if (tokenBlacklistService.isTokenBlacklisted(token)) {
            throw new SecurityException("Refresh token revogado");
        }

        // Valida assinatura e expiração (lança exception se falhar)
        tokenService.validateAndGetClaims(token);

        if (!tokenService.isRefreshToken(token)) {
            throw new IllegalArgumentException("Token não é um Refresh Token");
        }

        // 3. Reconstruir o Subject
        // Como o Refresh Token dura muito (ex: 30 dias), é VITAL ir no banco ver se o usuário ainda existe/está ativo
        String username = tokenService.extractUsername(token);
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não existe mais"));

        if (!user.isEnabled()) {
            throw new SecurityException("Conta desativada");
        }

        // Recria as roles (caso tenham mudado no banco desde o último login)
        List<String> roles = user.getRoles().stream().toList();

        // 4. Gera APENAS um novo Access Token (Refresh Rotation é opcional, por enquanto mantemos o mesmo refresh)
        Subject subject = new Subject(
                user.getUsername(),
                roles,
                Map.of("source", "refresh_token"),
                user.isEnabled() // isVerified
        );

        String newAccessToken = tokenService.generateAccessToken(subject);

        return new TokenResponse(
                newAccessToken,
                token, // Devolvemos o mesmo refresh token (ou gere um novo para rotação)
                "Bearer",
                jwtProperties.getAccessTokenExpiration()
        );
    }

}