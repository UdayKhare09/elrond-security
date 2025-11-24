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
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

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
        // Check if username already exists
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Create new user
        ElrondUser user = ElrondUser.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(false)
                .emailVerified(false)
                .mfaEnabled(false)
                .build();

        user = userRepository.save(user);

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

        verificationToken.setUsed(true);
        verificationTokenRepository.save(verificationToken);
    }

    public LoginResponse login(LoginRequest request) {
        // Find user by username or email
        ElrondUser user = userRepository.findByUsername(request.getUsernameOrEmail())
                .orElseGet(() -> userRepository.findByEmail(request.getUsernameOrEmail())
                        .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials")));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials");
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
        return new LoginResponse(token);
    }

    public LoginResponse verifyMfa(MfaVerificationRequest request) {
        // Validate MFA token
        if (request.getMfaToken() == null || request.getMfaToken().isEmpty()) {
            throw new InvalidTokenException("MFA token is required");
        }

        String username = jwtService.extractUsername(request.getMfaToken());
        if (jwtService.isMfaToken(request.getMfaToken()) ||
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
    public void enableMfa(String username, String totpCode) {
        ElrondUser user = getUserByUsernameOrEmail(username);

        if (user.getMfaSecret() == null) {
            throw new IllegalStateException("MFA setup not completed");
        }

        // Verify TOTP code
        try {
            int code = Integer.parseInt(totpCode);
            if (!totpService.verifyCode(user.getMfaSecret(), code)) {
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        } catch (NumberFormatException e) {
            throw new InvalidCredentialsException("Invalid MFA code format");
        }

        user.setMfaEnabled(true);
        userRepository.save(user);
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
}
