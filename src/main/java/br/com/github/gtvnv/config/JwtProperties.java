package br.com.github.gtvnv.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "aegis.jwt")
public class JwtProperties {
    // Expiração em segundos
    private long accessTokenExpiration = 300; // 5 minutos (Curto, para forçar rotação)
    private long refreshTokenExpiration = 86400; // 24 horas

    // Getters e Setters (Lombok @Data funciona aqui se tiver habilitado)
    public long getAccessTokenExpiration() { return accessTokenExpiration; }
    public void setAccessTokenExpiration(long accessTokenExpiration) { this.accessTokenExpiration = accessTokenExpiration; }
    public long getRefreshTokenExpiration() { return refreshTokenExpiration; }
    public void setRefreshTokenExpiration(long refreshTokenExpiration) { this.refreshTokenExpiration = refreshTokenExpiration; }
}