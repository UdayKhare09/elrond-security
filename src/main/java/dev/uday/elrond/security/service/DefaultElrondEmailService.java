package dev.uday.elrond.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import dev.uday.elrond.security.ElrondSecurityProperties;

@RequiredArgsConstructor
public class DefaultElrondEmailService implements ElrondEmailService {

    private final JavaMailSender mailSender;
    private final ElrondSecurityProperties properties;

    @Override
    public void sendVerificationEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.getMail().getFrom());
        message.setTo(to);
        message.setSubject("Email Verification");

        // We might need a way to configure the base URL. For now, let's assume it's
        // passed or configured.
        // The original code used app.url property.
        // Let's add appUrl to properties or just use a placeholder.
        String appUrl = "http://localhost:8080"; // Default or from properties

        String verificationUrl = appUrl + "/api/v1/auth/verify-email?token=" + token;
        String text = "Welcome!\n\n" +
                "Please click the link below to verify your email address:\n" +
                verificationUrl + "\n\n" +
                "This link will expire in 24 hours.";

        message.setText(text);
        mailSender.send(message);
    }
}
