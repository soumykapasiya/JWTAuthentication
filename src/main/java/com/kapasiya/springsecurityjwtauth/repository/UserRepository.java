package com.kapasiya.springsecurityjwtauth.repository;

import com.kapasiya.springsecurityjwtauth.entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmail(String username);

    Boolean existsByName(String username);

    Boolean existsByEmail(String email);
}