package com.example.newsfeed.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    // Redis에 저장할 때 사용할 블랙리스트 키의 접두사
    private static final String BLACKLIST_PREFIX = "blacklist";

    // Redis에 접근하기 위한 템플릿 객체 (Spring이 주입함)
    private final RedisTemplate<String,Object> redisTemplate;


    // 주어진 JWT 토큰을 블랙리스트에 추가하는 메서드
    public void blacklistToken(String token, long expirationMillis){
        String key = BLACKLIST_PREFIX + token; // Redis 키 : "blacklist : {토큰값}"
        
        // Redis 객체에 저장할 정보
        redisTemplate.opsForValue().set(
                key, // 저장할 키 이름
                "logout", // 저장할 값
                expirationMillis, // 유지할 시간
                TimeUnit.MILLISECONDS // 유지 시간 단위
            );
    }

    // JWT 토큰이 블랙리스트에 포함되어 있는지 확인하는 메서드
    public boolean isTokenBlacklisted(String token){
        String key = BLACKLIST_PREFIX + token;
        return redisTemplate.hasKey(key);

    }

}
