package dev.uday.elrond.security.config;

import dev.uday.elrond.security.ElrondSecurityProperties;
import dev.uday.elrond.security.filter.JwtAuthenticationFilter;
import dev.uday.elrond.security.repository.ElrondUserRepository;
import dev.uday.elrond.security.repository.VerificationTokenRepository;
import dev.uday.elrond.security.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Import({ ElrondPersistenceConfig.class, ElrondMailConfig.class })
@ComponentScan(basePackages = "dev.uday.elrond.security")
public class ElrondSecurityConfig {

    private final ElrondSecurityProperties properties;

    @Bean
    @ConditionalOnMissingBean(ElrondUserDetailsService.class)
    public ElrondUserDetailsService elrondUserDetailsService(ElrondUserRepository userRepository) {
        return new DefaultElrondUserDetailsService(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public ElrondAuthService elrondAuthService(
            ElrondUserRepository userRepository,
            VerificationTokenRepository verificationTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            TotpService totpService,
            ElrondEmailService emailService) {
        return new ElrondAuthService(userRepository, verificationTokenRepository, passwordEncoder, jwtService, totpService, emailService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationProvider authenticationProvider) throws Exception {
        // Build public URLs array
        String[] publicUrls = properties.getPublicUrls().isEmpty()
                ? new String[] {
                        "/api/v1/auth/register",
                        "/api/v1/auth/login",
                        "/api/v1/auth/verify-email",
                        "/api/v1/auth/mfa/verify"
                }
                : properties.getPublicUrls().toArray(new String[0]);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(properties.getCors().getAllowedOrigins());
                    config.setAllowedMethods(properties.getCors().getAllowedMethods());
                    config.setAllowedHeaders(properties.getCors().getAllowedHeaders());
                    config.setAllowCredentials(properties.getCors().isAllowCredentials());
                    return config;
                }))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicUrls).permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationProvider authenticationProvider(ElrondUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(properties.getPassword().getStrength());
    }
}
