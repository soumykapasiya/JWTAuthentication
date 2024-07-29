package com.kapasiya.springsecurityjwtauth.payload.request;

import lombok.*;

import java.util.Set;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class SignupRequest {
    private String name;
    private String email;
    private Set<String> roles;
    private String password;
}
