package dev.uday.elrond.security;

import dev.uday.elrond.security.config.ElrondSecurityConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(ElrondSecurityConfig.class)
public @interface ElrondSecurity {
}
