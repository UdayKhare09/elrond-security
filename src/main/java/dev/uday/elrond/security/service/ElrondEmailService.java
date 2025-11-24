package dev.uday.elrond.security.service;

public interface ElrondEmailService {
    void sendVerificationEmail(String to, String token);
}
