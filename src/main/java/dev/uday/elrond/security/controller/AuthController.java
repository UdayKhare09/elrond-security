package dev.uday.elrond.security.controller;
import dev.uday.elrond.security.dto.*;
import dev.uday.elrond.security.service.ElrondAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final ElrondAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<LoginResponse> verifyMfa(@Valid @RequestBody MfaVerificationRequest request) {
        return ResponseEntity.ok(authService.verifyMfa(request));
    }

    @PostMapping("/mfa/setup")
    public ResponseEntity<MfaSetupResponse> setupMfa(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(401).build();
        }
        String username = authentication.getName();
        return ResponseEntity.ok(authService.setupMfa(username));
    }

    @PostMapping("/mfa/disable")
    public ResponseEntity<Void> disableMfa(Authentication authentication, @RequestParam String totpCode) {
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(401).build();
        }
        String username = authentication.getName();
        authService.disableMfa(username, totpCode);
        return ResponseEntity.ok().build();
    }
}
