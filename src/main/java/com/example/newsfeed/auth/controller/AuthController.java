package com.example.newsfeed.auth.controller;

import com.example.newsfeed.auth.dto.LoginRequestDto;
import com.example.newsfeed.auth.dto.LoginResponseDto;
import com.example.newsfeed.domain.user.dto.UserRequestDto;
import com.example.newsfeed.domain.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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




    // 로그인
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto dto){

        String token = userService.login(dto);

        return ResponseEntity.ok(new LoginResponseDto(token));
    }


    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<Long> signup(@Valid @RequestBody UserRequestDto userRequestDto){
        Long id = userService.signup(userRequestDto);
        return ResponseEntity.status(HttpStatus.OK).body(id);
    }
}
