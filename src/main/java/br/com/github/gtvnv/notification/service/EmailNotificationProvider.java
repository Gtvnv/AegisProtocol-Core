package br.com.github.gtvnv.notification.service;

import br.com.github.gtvnv.notification.config.NotificationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import java.io.IOException;

/**
 * Implementação padrão de NotificationProvider — e-mail via
 * spring-boot-starter-mail (SMTP configurado em spring.mail.*).
 */
@RequiredArgsConstructor
public class EmailNotificationProvider implements NotificationProvider {

    private final MailSender mailSender;
    private final NotificationProperties properties;

    @Override
    public void send(String toAddress, String subject, String body) throws IOException {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(properties.getFromAddress());
            message.setTo(toAddress);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
        } catch (MailException e) {
            throw new IOException("Falha ao enviar e-mail para " + toAddress, e);
        }
    }
}
