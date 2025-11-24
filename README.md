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

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>dev.uday</groupId>
    <artifactId>elrond-security-lib</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 2. Enable Elrond Security

Add `@ElrondSecurity` to your main application class:

```java
@SpringBootApplication
@ElrondSecurity
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### 3. Configure Properties

Add to your `application.yml`:

```yaml
elrond:
  security:
    jwt:
      secret-key: "your-secret-key-must-be-at-least-256-bits-long-for-hs256-algorithm"
      expiration: 86400000  # 24 hours
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

## Usage

The library automatically provides the following endpoints (if you create a controller or use the default ones):

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login
- `GET /api/v1/auth/verify-email?token=...` - Verify email
- `POST /api/v1/auth/mfa/setup` - Setup MFA
- `POST /api/v1/auth/mfa/verify` - Verify MFA code

## Customization

### Custom User Entity

By default, the library provides an `ElrondUser` entity. To use your own custom user:

1. Disable the default:
```yaml
elrond:
  security:
    db:
      enabled: false
```

2. Create your own user entity and implement `UserDetails`
3. Provide your own `ElrondUserDetailsService` bean

### Custom Email Service

Provide your own `ElrondEmailService` bean:

```java
@Bean
public ElrondEmailService customEmailService() {
    return new MyCustomEmailService();
}
```

### Custom Filters

All security components are customizable via `@ConditionalOnMissingBean`. Simply provide your own beans to override defaults.

## What's Included

- **Models**: `ElrondUser`, `VerificationToken`
- **Services**: `JwtService`, `TotpService`, `ElrondAuthService`, `ElrondEmailService`
- **DTOs**: `LoginRequest`, `LoginResponse`, `RegisterRequest`, `MfaSetupResponse`, `MfaVerificationRequest`
- **Exceptions**: `InvalidCredentialsException`, `InvalidTokenException`, `UserNotFoundException`, `UserAlreadyExistsException`
- **Security Config**: Pre-configured Spring Security with JWT filter

## License

MIT License
