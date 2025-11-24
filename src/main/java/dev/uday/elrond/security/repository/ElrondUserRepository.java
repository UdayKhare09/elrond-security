package dev.uday.elrond.security.repository;

import dev.uday.elrond.security.model.ElrondUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ElrondUserRepository extends JpaRepository<ElrondUser, Long> {
    Optional<ElrondUser> findByUsername(String username);

    Optional<ElrondUser> findByEmail(String email);
}
