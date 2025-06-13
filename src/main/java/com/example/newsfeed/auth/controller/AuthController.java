package com.example.newsfeed.auth.controller;

import com.example.newsfeed.auth.dto.LoginResponse;
import com.example.newsfeed.auth.dto.LoginRequest;
import com.example.newsfeed.auth.service.TokenBlacklistService;
import com.example.newsfeed.domain.user.service.UserService;
import com.example.newsfeed.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;


    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest){

        String token = userService.login(loginRequest);

        return ResponseEntity.ok(new LoginResponse(token));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout (HttpServletRequest request){
        String token = jwtTokenProvider.resolveToken(request);

        if(token != null && jwtTokenProvider.validateToken(token)){
            long expiration = jwtTokenProvider.getExpiration(token);
            tokenBlacklistService.blacklistToken(token,expiration);
        }

        return ResponseEntity.noContent().build();
    }
}
