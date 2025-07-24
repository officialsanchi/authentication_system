package com.authentication.AuthenticationSystem.data.repository;

import com.authentication.AuthenticationSystem.data.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PrimaryUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
    AppUser findPrimaryUserByEmail(String email);
}
