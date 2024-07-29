package com.kapasiya.springsecurityjwtauth.repository;

import com.kapasiya.springsecurityjwtauth.entities.ERole;
import com.kapasiya.springsecurityjwtauth.entities.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}