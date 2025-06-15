package com.example.newsfeed.auth.dto;

import lombok.Getter;

@Getter
public class LoginRequestDto {
    private String userEmail;
    private String password;
}
