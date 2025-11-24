package dev.uday.elrond.security.config;

import dev.uday.elrond.security.model.ElrondUser;
import dev.uday.elrond.security.repository.ElrondUserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@ConditionalOnProperty(prefix = "elrond.security.db", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableJpaRepositories(basePackageClasses = ElrondUserRepository.class)
@EntityScan(basePackageClasses = ElrondUser.class)
public class ElrondPersistenceConfig {
}
