package br.com.github.gtvnv.crypto;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

/**
 * Onde o par de chaves RSA (e o histórico de rotação) realmente mora.
 * KeyManagerService cuida de kid, keyring em memória e orquestração da
 * rotação — tudo o que é I/O de fato passa por aqui, então trocar a fonte
 * (arquivo local, Vault, um HSM real amanhã) não muda uma linha da
 * orquestração.
 *
 * Implementações: FileKeyMaterialStore (padrão) e
 * br.com.github.gtvnv.crypto.vault.VaultKeyMaterialStore (satélite
 * KMS/Vault real — aegis.jwt.key-source=vault).
 */
public interface KeyMaterialStore {

    record LoadedKeyMaterial(RSAPrivateKey privateKey, RSAPublicKey publicKey, boolean writable) {}

    /** Carrega o par ATUAL. As chaves precisam já existir — nenhum store gera o par inicial sozinho. */
    LoadedKeyMaterial loadCurrent() throws IOException;

    /** Persiste um novo par como "atual" — chamado só durante rotate(). */
    void writeCurrent(RSAPrivateKey privateKey, RSAPublicKey publicKey) throws IOException;

    /** Arquiva uma chave pública que estava saindo de "atual", sob o kid dela — não-destrutivo se já existir. */
    void archivePublicKey(String kid, RSAPublicKey publicKey) throws IOException;

    /** Carrega uma chave pública arquivada, se ainda existir (pode ter sido podada pela retenção). */
    Optional<RSAPublicKey> loadArchivedPublicKey(String kid) throws IOException;

    /** Histórico de kids já arquivados, do mais antigo pro mais novo (o atual nunca entra aqui). */
    List<String> loadArchiveHistory() throws IOException;

    void appendArchiveHistory(String kid) throws IOException;

    /** Remove uma chave arquivada que saiu da janela de retenção. */
    void deleteArchivedKey(String kid) throws IOException;
}
