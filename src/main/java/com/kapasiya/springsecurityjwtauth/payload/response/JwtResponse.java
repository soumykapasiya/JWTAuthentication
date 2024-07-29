package com.kapasiya.springsecurityjwtauth.payload.response;

import lombok.*;

import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String id;
    private String username;
    private String email;
    private List<String> roles;


    public JwtResponse(String jwt, String id, String username, String email, List<String> roles) {
    }
}
