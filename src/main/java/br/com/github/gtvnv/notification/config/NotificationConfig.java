package br.com.github.gtvnv.notification.config;

import br.com.github.gtvnv.notification.service.EmailNotificationProvider;
import br.com.github.gtvnv.notification.service.NotificationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.MailSender;

@Configuration
public class NotificationConfig {

    @Bean
    public NotificationProvider notificationProvider(MailSender mailSender, NotificationProperties properties) {
        return new EmailNotificationProvider(mailSender, properties);
    }
}
