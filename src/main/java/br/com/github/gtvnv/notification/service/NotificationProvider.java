package br.com.github.gtvnv.notification.service;

import java.io.IOException;

/**
 * Envio de notificação, isolado atrás de uma interface — igual o
 * KeyMaterialStore fez pro satélite KMS/Vault real, pra trocar o canal
 * (e-mail hoje, SMS/webhook amanhã) sem mexer em quem chama.
 */
public interface NotificationProvider {

    /** @throws IOException se o envio falhar — quem chama decide se isso é uma falha fatal ou não. */
    void send(String toAddress, String subject, String body) throws IOException;
}
