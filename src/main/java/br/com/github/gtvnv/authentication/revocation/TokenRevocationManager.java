package br.com.github.gtvnv.authentication.revocation;

public interface TokenRevocationManager {
    void revoke(String token, long ttlSeconds);
    boolean isRevoked(String token);
}