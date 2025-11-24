package dev.uday.elrond.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "elrond.security")
public class ElrondSecurityProperties {

    private List<String> publicUrls = new ArrayList<>();

    private Jwt jwt = new Jwt();
    private Db db = new Db();
    private Mail mail = new Mail();
    private Mfa mfa = new Mfa();
    private Cors cors = new Cors();
    private Password password = new Password();

    @Data
    public static class Jwt {
        private String secretKey;
        private long expiration = 86400000; // 1 day
        private long refreshExpiration = 604800000; // 7 days
    }

    @Data
    public static class Db {
        private boolean enabled = true;
    }

    @Data
    public static class Mail {
        private boolean enabled = true;
        private String from = "noreply@elrond.com";
    }

    @Data
    public static class Mfa {
        private String issuer = "Elrond";
    }

    @Data
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
        private List<String> allowedHeaders = List.of("*");
        private boolean allowCredentials = true;
    }

    @Data
    public static class Password {
        private int strength = 10;
    }
}
