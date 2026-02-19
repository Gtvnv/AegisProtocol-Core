package br.com.github.gtvnv.authentication.service;

import br.com.github.gtvnv.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AegisUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(userEntity -> User.builder()
                        .username(userEntity.getUsername())
                        .password(userEntity.getPassword())
                        .roles(userEntity.getRoles().toArray(new String[0]))

                        // 🔥 SOFT LOCK ATIVADO:
                        // Dizemos ao Spring que a conta está ATIVA (disabled=false) independente do banco.
                        // Isso garante que o login ocorra. A restrição será aplicada via Token depois.
                        .disabled(false)

                        .accountExpired(false)
                        .accountLocked(false)
                        .credentialsExpired(false)
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}