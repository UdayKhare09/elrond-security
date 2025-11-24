package dev.uday.elrond.security.config;

import dev.uday.elrond.security.ElrondSecurityProperties;
import dev.uday.elrond.security.service.DefaultElrondEmailService;
import dev.uday.elrond.security.service.ElrondEmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

@Configuration
@ConditionalOnProperty(prefix = "elrond.security.mail", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass(JavaMailSender.class)
@RequiredArgsConstructor
public class ElrondMailConfig {

    private final ElrondSecurityProperties properties;

    @Bean
    @ConditionalOnMissingBean
    public ElrondEmailService elrondEmailService(JavaMailSender mailSender) {
        return new DefaultElrondEmailService(mailSender, properties);
    }
}
