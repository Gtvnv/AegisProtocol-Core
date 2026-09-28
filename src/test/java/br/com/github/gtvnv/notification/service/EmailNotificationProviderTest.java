package br.com.github.gtvnv.notification.service;

import br.com.github.gtvnv.notification.config.NotificationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailNotificationProviderTest {

    @Mock private MailSender mailSender;

    private NotificationProperties properties;
    private EmailNotificationProvider provider;

    @BeforeEach
    void setUp() {
        properties = new NotificationProperties();
        properties.setFromAddress("no-reply@aegisprotocol.example");
        provider = new EmailNotificationProvider(mailSender, properties);
    }

    @Test
    @DisplayName("send() monta a mensagem com from/to/subject/body corretos")
    void send_BuildsMessageWithCorrectFields() throws Exception {
        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);

        provider.send("alice@example.com", "Assunto do alerta", "Corpo do alerta");

        verify(mailSender).send(captor.capture());
        SimpleMailMessage sent = captor.getValue();
        assertThat(sent.getFrom()).isEqualTo("no-reply@aegisprotocol.example");
        assertThat(sent.getTo()).containsExactly("alice@example.com");
        assertThat(sent.getSubject()).isEqualTo("Assunto do alerta");
        assertThat(sent.getText()).isEqualTo("Corpo do alerta");
    }

    @Test
    @DisplayName("send() propaga falha do MailSender como IOException")
    void send_MailSenderThrows_WrapsAsIOException() {
        doThrow(new MailSendException("SMTP fora do ar")).when(mailSender).send(any(SimpleMailMessage.class));

        assertThatThrownBy(() -> provider.send("alice@example.com", "s", "b"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("alice@example.com");
    }
}
