package dev.uday.elrond.security.service;

import dev.uday.elrond.security.ElrondSecurityProperties;
import dev.uday.elrond.security.dto.*;
import dev.uday.elrond.security.exception.*;
import dev.uday.elrond.security.model.ElrondUser;
import dev.uday.elrond.security.model.VerificationToken;
import dev.uday.elrond.security.repository.ElrondUserRepository;
import dev.uday.elrond.security.repository.VerificationTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnMissingBean(name = "elrondAuthService")
public class ElrondAuthService {

    private final ElrondUserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final ElrondEmailService emailService;
    private final ElrondSecurityProperties properties;

    @Transactional
    public void register(RegisterRequest request) {
        // Sanitize inputs
        String sanitizedUsername = sanitizeInput(request.getUsername());
        String sanitizedEmail = sanitizeInput(request.getEmail());
        String sanitizedFirstName = sanitizeInput(request.getFirstName());
        String sanitizedLastName = request.getLastName() != null ? sanitizeInput(request.getLastName()) : null;

        // Check if username already exists
        if (userRepository.findByUsername(sanitizedUsername).isPresent()) {
            throw new UserAlreadyExistsException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.findByEmail(sanitizedEmail).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Create new user
        ElrondUser user = ElrondUser.builder()
                .email(sanitizedEmail)
                .username(sanitizedUsername)
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(sanitizedFirstName)
                .lastName(sanitizedLastName)
                .enabled(false)
                .emailVerified(false)
                .mfaEnabled(false)
                .build();

        user = userRepository.save(user);
        log.info("New user registered: {}", sanitizedUsername);

        // Create verification token
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        verificationTokenRepository.save(verificationToken);

        // Send verification email
        emailService.sendVerificationEmail(user.getEmail(), token);
    }

    @Transactional
    public void verifyEmail(String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid verification token"));

        if (verificationToken.isUsed()) {
            throw new InvalidTokenException("Token has already been used");
        }

        if (verificationToken.isExpired()) {
            throw new InvalidTokenException("Token has expired");
        }

        ElrondUser user = verificationToken.getUser();
        user.setEmailVerified(true);
        user.setEnabled(true);
        userRepository.save(user);
        log.info("Email verified for user: {}", user.getUsername());

        verificationToken.setUsed(true);
        verificationTokenRepository.save(verificationToken);
    }

    public LoginResponse login(LoginRequest request) {
        // Find user by username or email
        ElrondUser user = userRepository.findByUsername(request.getUsernameOrEmail())
                .orElseGet(() -> userRepository.findByEmail(request.getUsernameOrEmail())
                        .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials")));

        // Check if account is locked
        if (properties.getAccountLockout().isEnabled() && !user.isAccountNonLocked()) {
            log.warn("Login attempt for locked account: {}", user.getUsername());
            throw new InvalidCredentialsException("Account is locked due to multiple failed login attempts. Please try again later.");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Failed login attempt for user: {}", user.getUsername());
            handleFailedLogin(user);
            throw new InvalidCredentialsException("Invalid credentials");
        }

        // Reset failed login attempts on successful login
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }

        // Check if user is enabled
        if (!user.isEnabled()) {
            throw new InvalidCredentialsException("Account not verified. Please verify your email.");
        }

        // Check if MFA is enabled
        if (user.isMfaEnabled()) {
            if (request.getTotpCode() == null || request.getTotpCode().isEmpty()) {
                // MFA required, return temporary token
                String mfaToken = jwtService.generateMfaToken(user.getUsername());
                return new LoginResponse(mfaToken, true);
            } else {
                // Verify MFA code
                try {
                    int code = Integer.parseInt(request.getTotpCode());
                    if (!totpService.verifyCode(user.getMfaSecret(), code)) {
                        throw new InvalidCredentialsException("Invalid MFA code");
                    }
                } catch (NumberFormatException e) {
                    throw new InvalidCredentialsException("Invalid MFA code format");
                }
            }
        }

        // Generate JWT token
        String token = jwtService.generateToken(user.getUsername());
        log.info("Successful login for user: {}", user.getUsername());
        return new LoginResponse(token);
    }

    public LoginResponse verifyMfa(MfaVerificationRequest request) {
        // Validate MFA token
        if (request.getMfaToken() == null || request.getMfaToken().isEmpty()) {
            throw new InvalidTokenException("MFA token is required");
        }

        String username = jwtService.extractUsername(request.getMfaToken());
        if (!jwtService.isMfaToken(request.getMfaToken()) ||
                !jwtService.validateToken(request.getMfaToken(), username)) {
            throw new InvalidTokenException("Invalid MFA token");
        }

        // Get user
        ElrondUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Verify TOTP code
        try {
            int code = Integer.parseInt(request.getTotpCode());
            if (!totpService.verifyCode(user.getMfaSecret(), code)) {
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        } catch (NumberFormatException e) {
            throw new InvalidCredentialsException("Invalid MFA code format");
        }

        // Generate full JWT token
        String token = jwtService.generateToken(user.getUsername());
        return new LoginResponse(token);
    }

    @Transactional
    public MfaSetupResponse setupMfa(String username) {
        ElrondUser user = getUserByUsernameOrEmail(username);

        if (user.isMfaEnabled()) {
            throw new IllegalStateException("MFA is already enabled");
        }

        // Generate secret
        String secret = totpService.generateSecret();
        user.setMfaSecret(secret);
        userRepository.save(user);

        // Generate QR code URL
        String qrCodeUrl = totpService.generateQrCodeUrl(secret, user.getUsername(), properties.getMfa().getIssuer());

        return new MfaSetupResponse(secret, qrCodeUrl);
    }


    @Transactional
    public void disableMfa(String username, String totpCode) {
        ElrondUser user = getUserByUsernameOrEmail(username);

        if (!user.isMfaEnabled()) {
            throw new IllegalStateException("MFA is not enabled");
        }

        // Verify TOTP code before disabling
        try {
            int code = Integer.parseInt(totpCode);
            if (!totpService.verifyCode(user.getMfaSecret(), code)) {
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        } catch (NumberFormatException e) {
            throw new InvalidCredentialsException("Invalid MFA code format");
        }

        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        userRepository.save(user);
    }

    private ElrondUser getUserByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsername(usernameOrEmail)
                .orElseGet(() -> userRepository.findByEmail(usernameOrEmail)
                        .orElseThrow(() -> new UserNotFoundException("User not found")));
    }

    private String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        // Remove potential XSS and SQL injection characters
        return input.trim()
                .replaceAll("[<>\"'%;()&+]", "")
                .replaceAll("\\s+", " ");
    }

    private void handleFailedLogin(ElrondUser user) {
        if (!properties.getAccountLockout().isEnabled()) {
            return;
        }

        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= properties.getAccountLockout().getMaxFailedAttempts()) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(
                    properties.getAccountLockout().getLockoutDurationMinutes()));
        }

        userRepository.save(user);
    }
}
