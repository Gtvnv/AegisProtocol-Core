package br.com.github.gtvnv.authentication.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,   // "Bearer"
        long expiresIn      // segundos
) {}