# Elrond Security Library

A plug-and-play Spring Boot security library providing JWT authentication, email verification, and MFA support.

## Features

- 🔐 **JWT Authentication**: Stateless authentication using JSON Web Tokens
- 📧 **Email Verification**: User registration with email confirmation
- 🔑 **Multi-Factor Authentication (MFA)**: TOTP-based MFA support
- 🛡️ **Spring Security Integration**: Seamless integration with Spring Security
- ⚙️ **Customizable**: Override default implementations with your own
- 📦 **Plug-and-Play**: Just add the annotation and configure properties

## Quick Start

### 1. Add Dependency

Add to your `pom.xml` (coordinates match this project's `pom.xml`):

```xml
<dependency>
    <groupId>dev.uday</groupId>
    <artifactId>elrond-security</artifactId>
    <version>0.0.1</version>
</dependency>
```

If you are using a published snapshot or a different version in your repository, replace the version accordingly.

### Using GitHub Packages (Maven)

This artifact is published to GitHub Packages under the repository `UdayKhare09/elrond-security`. To consume it from Maven add the GitHub Packages repository to your `pom.xml` (or configure it in your `settings.xml`).

Add this repository block to your `pom.xml`:

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/UdayKhare09/elrond-security</url>
  </repository>
</repositories>
```

### 2. Enable Elrond Security

Add `@ElrondSecurity` to your main application class:

```java
@SpringBootApplication
@ElrondSecurity
public class MyApplication {
    static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### 3. Configure Properties

Example `application.yml` configuration. The library binds to the `elrond.security` prefix.

```yaml
elrond:
  security:
    jwt:
      secret-key: "your-secret-key-must-be-at-least-256-bits-long-for-hs256-algorithm"
      expiration: 86400000  # 24 hours in ms
    public-urls:
      - "/api/v1/auth/**"
      - "/actuator/**"
    db:
      enabled: true
    mail:
      enabled: true
      from: "noreply@yourapp.com"
    mfa:
      issuer: "YourAppName"
    cors:
      allowed-origins: 
        - "http://localhost:3000"
      allowed-methods: 
        - "GET"
        - "POST"
        - "PUT"
        - "DELETE"
      allowed-headers: 
        - "*"
      allow-credentials: true
    password:
      strength: 10 # BCrypt strength (4-31)

spring:
  mail:
    host: smtp.gmail.com
    port: 587
    username: your-email@gmail.com
    password: your-app-password
    properties:
      mail.smtp.auth: true
      mail.smtp.starttls.enable: true

  datasource:
    url: jdbc:postgresql://localhost:5432/yourdb
    username: youruser
    password: yourpassword
    
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
```

Notes:
- The binding supports standard Spring relaxed binding (kebab-case, camelCase, etc.).
- Keep your JWT secret safe and long enough for your signing algorithm.

## Usage

Typical authentication endpoints (default controller names shown in the library):

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login
- `GET /api/v1/auth/verify-email?token=...` - Verify email
- `POST /api/v1/auth/mfa/setup` - Setup MFA
- `POST /api/v1/auth/mfa/verify` - Verify MFA code

If you provide your own controllers or disable parts of the auto-configuration, endpoints may vary.

## Customization

### Custom User Entity

By default the library provides an `ElrondUser` entity and default persistence beans. To use your own custom user:

1. Disable the default DB-backed user store:
```yaml
elrond:
  security:
    db:
      enabled: false
```
2. Create your own user entity and implement `UserDetails`.
3. Provide your own `ElrondUserDetailsService` (or a bean with the appropriate contract) so Spring Security can load users.

### Custom Email Service

Provide your own `ElrondEmailService` bean to override the default email behavior:

```java
@Bean
public ElrondEmailService customEmailService() {
    return new MyCustomEmailService();
}
```

### Custom Filters and Beans

Most beans in the auto-configuration are `@ConditionalOnMissingBean`, so just provide your own beans to override the defaults.

## What's Included

- Models: `ElrondUser`, `VerificationToken`
- Services: `JwtService`, `TotpService`, `ElrondAuthService`, `ElrondEmailService` (default implementations)
- DTOs: `LoginRequest`, `LoginResponse`, `RegisterRequest`, `MfaSetupResponse`, `MfaVerificationRequest`
- Exceptions: `InvalidCredentialsException`, `InvalidTokenException`, `UserNotFoundException`, `UserAlreadyExistsException`
- Security Config: pre-configured Spring Security with a JWT authentication filter

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file for details or view it online:

https://www.apache.org/licenses/LICENSE-2.0
