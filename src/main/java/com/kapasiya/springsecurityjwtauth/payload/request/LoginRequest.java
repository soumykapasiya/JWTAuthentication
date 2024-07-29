package com.kapasiya.springsecurityjwtauth.payload.request;


import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LoginRequest {

    private String email;
    private String password;
}
