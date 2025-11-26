package dev.uday.elrond.security.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import dev.uday.elrond.security.ElrondSecurityProperties;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final ElrondSecurityProperties properties;

    private SecretKey getSigningKey() {
        byte[] keyBytes = properties.getJwt().getSecretKey().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username, properties.getJwt().getExpiration());
    }

    public String generateMfaToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("mfa", true);
        // MFA token usually has shorter expiration, let's use 5 minutes hardcoded or
        // add to properties
        // The original code had 300000 (5 mins).
        return createToken(claims, username, 300000);
    }

    private String createToken(Map<String, Object> claims, String subject, long expirationTime) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public boolean isMfaToken(String token) {
        Claims claims = extractClaims(token);
        Boolean mfaFlag = claims.get("mfa", Boolean.class);
        return mfaFlag != null && mfaFlag;
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            boolean isValid = extractedUsername.equals(username) && !isTokenExpired(token);
            if (!isValid) {
                log.warn("Invalid JWT token for user: {}", username);
            }
            return isValid;
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token for user: {}", username);
            return false;
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token for user: {}", username);
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT validation failed for user: {}", username);
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }
}
