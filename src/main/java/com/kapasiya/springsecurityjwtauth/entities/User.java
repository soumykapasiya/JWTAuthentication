package com.kapasiya.springsecurityjwtauth.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.HashSet;
import java.util.Set;

@Document
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@ToString
@Builder
public class User
{
    @Id
    private String id;
    private String name;
    private String email;
    private String password;

    @DBRef
    private Set<Role> roles = new HashSet<>();

    public User(String username, String email, String encode) {
    }
}
